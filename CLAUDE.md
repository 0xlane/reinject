# Project Conventions

## AI-Assisted Content

When an article is written with AI assistance, add the `ai_assisted` flag to its front matter:

```yaml
ai_assisted: true
```

## Tags vs Keywords

- **Tags** (`tags`): Keep clean and concise. Use them for indexing and linking related articles. Avoid noise.
- **Keywords** (`keywords`): Use for SEO-only terms that don't belong in the tag index.

Do not pollute the tag list with SEO-driven keywords — put those in `keywords` instead.

## Blockquotes & Callouts

Use [GitHub Alert syntax](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax#alerts) for callout boxes. Available types:

```markdown
> [!NOTE] Optional title
> Supplementary information the reader should be aware of.

> [!TIP] Optional title
> Helpful advice, code pointers, or resource links.

> [!IMPORTANT] Optional title
> Key information required to achieve the goal.

> [!WARNING] Optional title
> Potential issues or caveats the reader should watch for.

> [!CAUTION] Optional title
> Serious risks or irreversible consequences.
```

Guidelines:
- Choose the type that matches the **intent**.
- Keep the title short (a few words). If unnecessary, omit it — the type label alone is sufficient.
- Plain blockquotes (`> text`) are for quoted text (references, citations). Do not use them as callout boxes.

## Theme Management

Do not embed themes directly in the blog project. Themes must be Git submodules. When publishing changes that include theme modifications:

1. Push theme changes to the theme's remote repository first.
2. Then push the main repository.

This ensures the submodule commit referenced by the main repo is available when remote CI builds the site.
