/**
 * QuickFW Documentation Site JavaScript
 * Handles navigation, tabs, search, and interactive elements
 */

(function() {
    'use strict';

    // ═══════════════════════════════════════════════════════════════════
    // Mobile Navigation Toggle
    // ═══════════════════════════════════════════════════════════════════
    const navToggle = document.querySelector('.nav-toggle');
    const navMenu = document.querySelector('.nav-menu');

    if (navToggle && navMenu) {
        navToggle.addEventListener('click', function() {
            navMenu.classList.toggle('active');
            
            // Animate hamburger
            const spans = navToggle.querySelectorAll('span');
            if (navMenu.classList.contains('active')) {
                spans[0].style.transform = 'rotate(45deg) translate(5px, 5px)';
                spans[1].style.opacity = '0';
                spans[2].style.transform = 'rotate(-45deg) translate(5px, -5px)';
            } else {
                spans[0].style.transform = '';
                spans[1].style.opacity = '';
                spans[2].style.transform = '';
            }
        });

        // Close menu on outside click
        document.addEventListener('click', function(e) {
            if (!navToggle.contains(e.target) && !navMenu.contains(e.target)) {
                navMenu.classList.remove('active');
                const spans = navToggle.querySelectorAll('span');
                spans.forEach(span => {
                    span.style.transform = '';
                    span.style.opacity = '';
                });
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════════
    // Tab Switching
    // ═══════════════════════════════════════════════════════════════════
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const tabId = this.dataset.tab;
            
            // Deactivate all tabs
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            // Activate selected tab
            this.classList.add('active');
            const content = document.getElementById('tab-' + tabId);
            if (content) {
                content.classList.add('active');
            }
        });
    });

    // ═══════════════════════════════════════════════════════════════════
    // Smooth Scroll for Anchor Links
    // ═══════════════════════════════════════════════════════════════════
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            const href = this.getAttribute('href');
            if (href === '#') return;
            
            const target = document.querySelector(href);
            if (target) {
                e.preventDefault();
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
                
                // Update URL without jumping
                history.pushState(null, null, href);
            }
        });
    });

    // ═══════════════════════════════════════════════════════════════════
    // Sidebar Search (for docs pages)
    // ═══════════════════════════════════════════════════════════════════
    const sidebarSearch = document.querySelector('.sidebar-search input');
    if (sidebarSearch) {
        sidebarSearch.addEventListener('input', function() {
            const query = this.value.toLowerCase();
            const links = document.querySelectorAll('.sidebar-link');
            
            links.forEach(link => {
                const text = link.textContent.toLowerCase();
                const section = link.closest('.sidebar-section');
                
                if (text.includes(query)) {
                    link.style.display = 'block';
                    if (section) section.style.display = 'block';
                } else {
                    link.style.display = 'none';
                }
            });
            
            // Hide empty sections
            document.querySelectorAll('.sidebar-section').forEach(section => {
                const visibleLinks = section.querySelectorAll('.sidebar-link:not([style*="none"])');
                if (visibleLinks.length === 0 && query) {
                    section.style.display = 'none';
                } else {
                    section.style.display = 'block';
                }
            });
        });
    }

    // ═══════════════════════════════════════════════════════════════════
    // Active Sidebar Link Highlighting
    // ═══════════════════════════════════════════════════════════════════
    function updateActiveLink() {
        const currentPath = window.location.pathname;
        const sidebarLinks = document.querySelectorAll('.sidebar-link');
        
        sidebarLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === currentPath || 
                link.getAttribute('href') === currentPath.split('/').pop() ||
                (currentPath.includes(link.getAttribute('href')) && link.getAttribute('href') !== '#')) {
                link.classList.add('active');
            }
        });
    }
    
    updateActiveLink();

    // ═══════════════════════════════════════════════════════════════════
    // Code Block Copy Button
    // ═══════════════════════════════════════════════════════════════════
    document.querySelectorAll('pre').forEach(pre => {
        const button = document.createElement('button');
        button.className = 'copy-btn';
        button.textContent = 'Copy';
        button.style.cssText = `
            position: absolute;
            top: 0.5rem;
            right: 0.5rem;
            padding: 0.25rem 0.75rem;
            background: var(--color-bg-tertiary);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-sm);
            color: var(--color-text-secondary);
            font-size: 0.75rem;
            cursor: pointer;
            opacity: 0;
            transition: opacity 0.2s, background 0.2s;
        `;
        
        pre.style.position = 'relative';
        pre.appendChild(button);
        
        pre.addEventListener('mouseenter', () => button.style.opacity = '1');
        pre.addEventListener('mouseleave', () => button.style.opacity = '0');
        
        button.addEventListener('click', async function() {
            const code = pre.querySelector('code');
            const text = code ? code.textContent : pre.textContent;
            
            try {
                await navigator.clipboard.writeText(text);
                button.textContent = 'Copied!';
                button.style.background = 'var(--color-success)';
                button.style.color = 'white';
                
                setTimeout(() => {
                    button.textContent = 'Copy';
                    button.style.background = '';
                    button.style.color = '';
                }, 2000);
            } catch (err) {
                button.textContent = 'Failed';
                setTimeout(() => button.textContent = 'Copy', 2000);
            }
        });
    });

    // ═══════════════════════════════════════════════════════════════════
    // Table of Contents Generation (for docs pages)
    // ═══════════════════════════════════════════════════════════════════
    function generateTOC() {
        const content = document.querySelector('.docs-content');
        const tocContainer = document.querySelector('.toc');
        
        if (!content || !tocContainer) return;
        
        const headings = content.querySelectorAll('h2, h3');
        if (headings.length === 0) return;
        
        let tocHTML = '<h4>On this page</h4><ul>';
        
        headings.forEach(heading => {
            const level = heading.tagName.toLowerCase();
            const text = heading.textContent;
            const id = heading.id || text.toLowerCase().replace(/[^a-z0-9]+/g, '-');
            
            if (!heading.id) heading.id = id;
            
            tocHTML += `<li class="toc-${level}"><a href="#${id}">${text}</a></li>`;
        });
        
        tocHTML += '</ul>';
        tocContainer.innerHTML = tocHTML;
        
        // Highlight active section on scroll
        const tocLinks = tocContainer.querySelectorAll('a');
        
        window.addEventListener('scroll', function() {
            const scrollPos = window.scrollY + 100;
            
            headings.forEach((heading, index) => {
                if (heading.offsetTop <= scrollPos) {
                    tocLinks.forEach(link => link.classList.remove('active'));
                    if (tocLinks[index]) tocLinks[index].classList.add('active');
                }
            });
        });
    }
    
    generateTOC();

    // ═══════════════════════════════════════════════════════════════════
    // Search Functionality (if search page exists)
    // ═══════════════════════════════════════════════════════════════════
    const searchInput = document.getElementById('search-input');
    const searchResults = document.getElementById('search-results');
    
    if (searchInput && searchResults) {
        let searchIndex = [];
        
        // Load search index
        fetch('search-index.json')
            .then(r => r.json())
            .then(data => { searchIndex = data; })
            .catch(() => console.log('Search index not available'));
        
        searchInput.addEventListener('input', function() {
            const query = this.value.toLowerCase().trim();
            
            if (query.length < 2) {
                searchResults.innerHTML = '';
                return;
            }
            
            const results = searchIndex.filter(item => {
                return item.title.toLowerCase().includes(query) ||
                       item.content.toLowerCase().includes(query);
            }).slice(0, 10);
            
            if (results.length === 0) {
                searchResults.innerHTML = '<p class="no-results">No results found</p>';
                return;
            }
            
            searchResults.innerHTML = results.map(item => `
                <a href="${item.url}" class="search-result">
                    <h4>${highlightMatch(item.title, query)}</h4>
                    <p>${highlightMatch(item.excerpt, query)}</p>
                </a>
            `).join('');
        });
    }
    
    function highlightMatch(text, query) {
        const regex = new RegExp(`(${query})`, 'gi');
        return text.replace(regex, '<mark>$1</mark>');
    }

    // ═══════════════════════════════════════════════════════════════════
    // Keyboard Shortcuts
    // ═══════════════════════════════════════════════════════════════════
    document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd + K for search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const searchInput = document.getElementById('search-input');
            if (searchInput) searchInput.focus();
        }
        
        // Escape to close mobile menu
        if (e.key === 'Escape') {
            if (navMenu) navMenu.classList.remove('active');
        }
    });

    // ═══════════════════════════════════════════════════════════════════
    // Scroll Progress Indicator
    // ═══════════════════════════════════════════════════════════════════
    const progressBar = document.createElement('div');
    progressBar.className = 'scroll-progress';
    progressBar.style.cssText = `
        position: fixed;
        top: 64px;
        left: 0;
        width: 0%;
        height: 3px;
        background: var(--color-primary);
        z-index: 1001;
        transition: width 0.1s;
    `;
    document.body.appendChild(progressBar);
    
    window.addEventListener('scroll', function() {
        const winScroll = document.body.scrollTop || document.documentElement.scrollTop;
        const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
        const scrolled = (winScroll / height) * 100;
        progressBar.style.width = scrolled + '%';
    });

    // ═══════════════════════════════════════════════════════════════════
    // Image Lightbox
    // ═══════════════════════════════════════════════════════════════════
    document.querySelectorAll('.docs-content img').forEach(img => {
        img.style.cursor = 'zoom-in';
        img.addEventListener('click', function() {
            const lightbox = document.createElement('div');
            lightbox.className = 'lightbox';
            lightbox.innerHTML = `
                <div class="lightbox-overlay"></div>
                <img src="${this.src}" alt="${this.alt}">
                <button class="lightbox-close">&times;</button>
            `;
            lightbox.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 2000;
            `;
            
            const overlay = lightbox.querySelector('.lightbox-overlay');
            overlay.style.cssText = `
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0,0,0,0.9);
            `;
            
            const lightboxImg = lightbox.querySelector('img');
            lightboxImg.style.cssText = `
                max-width: 90%;
                max-height: 90%;
                position: relative;
                z-index: 1;
            `;
            
            const closeBtn = lightbox.querySelector('.lightbox-close');
            closeBtn.style.cssText = `
                position: absolute;
                top: 20px;
                right: 20px;
                background: none;
                border: none;
                color: white;
                font-size: 2rem;
                cursor: pointer;
                z-index: 2;
            `;
            
            document.body.appendChild(lightbox);
            document.body.style.overflow = 'hidden';
            
            const close = () => {
                lightbox.remove();
                document.body.style.overflow = '';
            };
            
            closeBtn.addEventListener('click', close);
            overlay.addEventListener('click', close);
            document.addEventListener('keydown', function esc(e) {
                if (e.key === 'Escape') {
                    close();
                    document.removeEventListener('keydown', esc);
                }
            });
        });
    });

    // ═══════════════════════════════════════════════════════════════════
    // External Links - Add indicator and security
    // ═══════════════════════════════════════════════════════════════════
    document.querySelectorAll('a').forEach(link => {
        const href = link.getAttribute('href');
        if (href && href.startsWith('http') && !href.includes(window.location.hostname)) {
            link.setAttribute('target', '_blank');
            link.setAttribute('rel', 'noopener noreferrer');
            
            // Add external link indicator
            if (!link.querySelector('.external-icon')) {
                const icon = document.createElement('span');
                icon.className = 'external-icon';
                icon.innerHTML = ' ↗';
                icon.style.fontSize = '0.8em';
                link.appendChild(icon);
            }
        }
    });

    console.log('QuickFW Documentation Site loaded successfully');
})();
