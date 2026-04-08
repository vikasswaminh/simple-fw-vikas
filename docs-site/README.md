# QuickFW Documentation Site

A modern, responsive static documentation site for the QuickFW firewall appliance, built for Cloudflare Pages hosting.

## Features

- **Comprehensive Documentation**: User Guide, Admin Guide, Developer Guide (API-first), and Deep Technical Documentation
- **API Reference**: Complete REST API documentation with examples
- **Code Review Based**: Technical documentation derived from line-by-line code analysis
- **Modern Design**: Dark theme, responsive layout, optimized for developers
- **Cloudflare Ready**: Pre-configured headers, redirects, and Wrangler config

## Project Structure

```
docs-site/
├── index.html              # Homepage with feature overview
├── css/
│   └── main.css           # Complete stylesheet with variables
├── js/
│   └── main.js            # Interactive components and utilities
├── guides/
│   ├── user-guide.html    # End-user documentation
│   ├── admin-guide.html   # System administration
│   └── developer-guide.html # API-first development guide
├── api-reference/
│   └── index.html         # Complete API endpoint reference
├── technical/
│   └── index.html         # Deep technical code analysis
├── _headers               # Cloudflare Pages headers config
├── _redirects             # URL redirects
├── wrangler.toml          # Cloudflare deployment config
└── README.md              # This file
```

## Deployment

### Cloudflare Pages (Recommended)

1. Fork or clone this repository
2. Log in to Cloudflare Dashboard
3. Navigate to Pages → Create a project
4. Connect your Git repository
5. Configure build settings:
   - Build command: (leave empty for static site)
   - Build output directory: `/`
6. Deploy!

### Local Testing

```bash
cd docs-site

# Using Python
python -m http.server 8000

# Using Node.js
npx serve .

# Using PHP
php -S localhost:8000
```

Then open http://localhost:8000

## Documentation Sections

### User Guide
- First login and dashboard overview
- Monitoring system status and traffic
- Viewing firewall rules and connections
- Account management

### Admin Guide
- ISO installation and first boot
- Network interface configuration (WAN/LAN)
- Firewall rule creation and zones
- NAT and port forwarding
- OSPF and BGP routing
- Backup/restore and maintenance

### Developer Guide (API-First)
- API architecture and authentication
- Request/response formats
- cURL, Python, JavaScript, and Go client examples
- Local development setup
- Contributing guidelines

### API Reference
- All 50+ REST endpoints
- Request/response schemas
- Error codes and handling
- Authentication details

### Technical Documentation
- System architecture and data flow
- Line-by-line code analysis of:
  - io crate (NFQUEUE implementation)
  - Firewall engine (nftables generation)
  - Authentication system
  - Input validation
  - API handlers
- Security analysis and best practices

## Browser Support

- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)
- Mobile browsers (iOS Safari, Chrome Mobile)

## License

Same as QuickFW project (MIT License)

## Contributing

When updating documentation:

1. Follow existing HTML/CSS patterns
2. Test responsiveness at multiple screen sizes
3. Verify all links work correctly
4. Update the README if structure changes
