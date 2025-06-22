# Code Embed Widget for Ghost Blog

A beautiful, responsive code embed widget that loads and displays code files directly from GitHub with syntax highlighting, copy functionality, and source linking.

## ✨ Features

- Clean, modern interface with light/dark mode support
- Automatically detects code language from file extension
- Copy entire code content to clipboard with visual feedback
- Direct link to view the original file on GitHub
- Automatic dark mode support based on system preferences
- Efficient caching and minimal overhead
- Simple installation with minimal configuration

## 🚀 Installation

### Step 1: Add Footer Code

1. Go to your Ghost Admin → **Settings** → **Code Injection**
2. Paste the following code into the **Site Footer** section:

[syntaxTemplate](/Ghost/Syntax/syntaxTemplate.html)

### Step 2: Use in Posts

To embed a code file in any post or page, simply add this HTML:

```html
<div class="code-embed-container" data-url="YOUR_GITHUB_RAW_URL_HERE">
📄 Loading [FileName].ext...
</div>
```

**The widget will automatically:**

- ✅ Detect the language from file extension  
- ✅ Add a "View Source" button linking to GitHub
- ✅ Show syntax highlighting and copy functionality

## 📖 Usage Examples

### PowerShell Script

```html
<div class="code-embed-container" data-url="https://raw.githubusercontent.com/username/repo/main/script.ps1">
📄 script.ps1
</div>
```

### JSON Configuration

```html
<div class="code-embed-container" data-url="https://raw.githubusercontent.com/username/repo/main/config.json">
📄 config.json
</div>
```

### Python Script

```html
<div class="code-embed-container" data-url="https://raw.githubusercontent.com/username/repo/main/app.py">
📄 app.py
</div>
```

## 🎯 Supported Languages

The widget automatically detects and highlights the following languages:

| Extension | Language | Display Name |
|-----------|----------|--------------|
| `.ps1`, `.psm1` | PowerShell | PowerShell |
| `.json` | JSON | JSON |
| `.js` | JavaScript | JavaScript |
| `.ts` | TypeScript | TypeScript |
| `.py` | Python | Python |
| `.css` | CSS | CSS |
| `.html` | HTML | HTML |
| `.xml` | XML | XML |
| `.yaml`, `.yml` | YAML | YAML |
| `.bicep` | Bicep | Bicep |
| `.kql`, `.kusto` | KQL | KQL |

## 🔧 Configuration Options

### Manual Language Override

```html
<div class="code-embed-container" 
     data-url="YOUR_URL" 
     data-type="javascript">
📄 Loading...
</div>
```

### Custom Source Link

```html
<div class="code-embed-container" 
     data-url="YOUR_RAW_URL"
     data-href="https://github.com/user/repo/blob/main/file.js">
📄 Loading...
</div>
```

### Custom Height

```html
<div class="code-embed-container" 
     data-url="YOUR_URL"
     style="max-height: 400px;">
📄 Loading...
</div>
```

## 🎨 Customization

### Changing Colors

Modify the CSS variables in the footer code:

```css
.code-embed-container {
    background: #f6f8fa; /* Light mode background */
    border-color: #d1d9e0; /* Border color */
}

@media (prefers-color-scheme: dark) {
    .code-embed-container {
        background: #0d1117; /* Dark mode background */
        border-color: #30363d; /* Dark border */
    }
}
```

### Adjusting Scrollbars

```css
.code-embed-content::-webkit-scrollbar {
    width: 12px; /* Scrollbar width */
    height: 12px; /* Scrollbar height */
}
```

## 🐛 Troubleshooting

### Code Not Loading

- ✅ Ensure the GitHub URL is a **raw** URL (starts with `raw.githubusercontent.com`)
- ✅ Check that the file is publicly accessible
- ✅ Verify the footer code is properly installed

### Styling Issues

- ✅ Clear browser cache
- ✅ Check for CSS conflicts with your theme
- ✅ Ensure the footer code is in the **Site Footer**, not header

### Scrollbar Problems

- ✅ The widget uses a two-container approach for proper scrollbar clipping
- ✅ Horizontal scrollbars are always visible for code readability

## 🌟 Advanced Features

### Automatic GitHub Integration

- **Auto-detects GitHub URLs** and creates proper source links
- **Converts raw URLs** to GitHub blob URLs automatically  
- **Custom source links** supported with `data-href` attribute

### Multiple Embeds Per Page

The widget supports unlimited code embeds on a single page:

```html
<div class="code-embed-container" data-url="URL_1">📄 File 1</div>
<div class="code-embed-container" data-url="URL_2">📄 File 2</div>
<div class="code-embed-container" data-url="URL_3">📄 File 3</div>
```

### Ghost Editor Preview

In the Ghost editor, you'll see a placeholder showing the filename. When published, this transforms into the full syntax-highlighted code block.

![CodeBlock](/Ghost/Syntax/.images/ghost_code_syn.png)

### Performance

- Code is fetched once and cached
- Prism.js loads language modules on-demand
- Minimal impact on page load times

## 📱 Browser Support

- ✅ **Chrome** (Full support including custom scrollbars)
- ✅ **Safari** (Full support including custom scrollbars)
- ✅ **Firefox** (Full support with standard scrollbars)
- ✅ **Edge** (Full support including custom scrollbars)

## 🔄 Updates

To update the widget:

1. Replace the footer code with the new version
2. Existing embeds will automatically use the new functionality
3. No changes needed to individual embed codes

## 📄 License

This code embed widget is open source and free to use in any Ghost blog.

## 🤝 Contributing

Found a bug or want to suggest an improvement? Feel free to:

- Report issues with specific GitHub URLs that don't work
- Suggest new language support
- Propose design improvements
