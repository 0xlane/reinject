+++
date = '{{ now.Format (default "2006-01-02 15:04:05" .Site.Params.dateFmt) }}'
draft = true
title = '{{ replace .File.ContentBaseName "-" " " | title }}'
+++
