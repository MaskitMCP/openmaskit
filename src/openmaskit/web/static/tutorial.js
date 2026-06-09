/**
 * Tutorial System for OpenMaskit
 * Interactive step-by-step tutorials with spotlight effects
 */

// Tutorial state manager
const TutorialManager = {
    STORAGE_KEY: 'maskit_tutorials_state',

    // Get completion state for all tutorials
    getState() {
        try {
            const stored = localStorage.getItem(this.STORAGE_KEY);
            return stored ? JSON.parse(stored) : {};
        } catch {
            return {};
        }
    },

    // Check if specific tutorial is completed
    isCompleted(tutorialId) {
        const state = this.getState();
        return state[tutorialId]?.completed || false;
    },

    // Mark tutorial as completed
    markCompleted(tutorialId) {
        const state = this.getState();
        state[tutorialId] = { completed: true, timestamp: Date.now() };
        try {
            localStorage.setItem(this.STORAGE_KEY, JSON.stringify(state));
        } catch (e) {
            console.warn('Failed to save tutorial state:', e);
        }
    },

    // Reset specific tutorial
    reset(tutorialId) {
        const state = this.getState();
        delete state[tutorialId];
        try {
            localStorage.setItem(this.STORAGE_KEY, JSON.stringify(state));
        } catch (e) {
            console.warn('Failed to reset tutorial state:', e);
        }
    },

    // Reset all tutorials
    resetAll() {
        try {
            localStorage.removeItem(this.STORAGE_KEY);
        } catch (e) {
            console.warn('Failed to reset all tutorials:', e);
        }
    }
};

// Tutorial step sequencer
class Tutorial {
    constructor(definition) {
        this.id = definition.id;
        this.title = definition.title;
        this.steps = definition.steps;
        this.currentStep = 0;
        this.overlay = null;
        this.escapeHandler = null;
    }

    start() {
        this.currentStep = 0;
        this.createOverlay();
        this.showStep(0);
        this.setupScrollTracking();
    }

    setupScrollTracking() {
        // Track scroll and window resize to update positions
        this.scrollHandler = () => {
            if (this.overlay && this.currentStep < this.steps.length) {
                this.updatePositions();
            }
        };
        this.resizeHandler = () => {
            if (this.overlay && this.currentStep < this.steps.length) {
                this.updatePositions();
            }
        };

        window.addEventListener('scroll', this.scrollHandler, true); // Use capture to catch all scrolls
        window.addEventListener('resize', this.resizeHandler);
    }

    updatePositions() {
        const step = this.steps[this.currentStep];
        if (step.target) {
            this.highlightElement(step.target);
            this.positionPopover(step.target, step.position || 'bottom');
        }
    }

    createOverlay() {
        // Create spotlight overlay that dims everything
        this.overlay = document.createElement('div');
        this.overlay.className = 'tutorial-overlay';
        this.overlay.innerHTML = `
            <div class="tutorial-spotlight"></div>
            <svg class="tutorial-connector" width="100%" height="100%">
                <path d="" stroke-linecap="round"/>
            </svg>
            <div class="tutorial-highlight-box breathing"></div>
            <div class="tutorial-popover">
                <div class="tutorial-popover-header">
                    <h4 class="tutorial-popover-title"></h4>
                    <button class="tutorial-close-btn" aria-label="Exit tutorial">×</button>
                </div>
                <div class="tutorial-popover-body">
                    <p class="tutorial-step-text"></p>
                </div>
                <div class="tutorial-popover-footer">
                    <span class="tutorial-progress"></span>
                    <div class="tutorial-actions">
                        <button class="btn-tutorial-skip">Skip Tutorial</button>
                        <button class="btn-tutorial-prev" style="display:none;">Previous</button>
                        <button class="btn-tutorial-next">Next</button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(this.overlay);
        this.bindEvents();
    }

    showStep(index) {
        const step = this.steps[index];
        const popover = this.overlay.querySelector('.tutorial-popover');
        this._scrolledForFit = false;

        // Update popover content
        popover.querySelector('.tutorial-popover-title').textContent = this.title;
        popover.querySelector('.tutorial-step-text').textContent = step.text;
        popover.querySelector('.tutorial-progress').textContent = `Step ${index + 1} of ${this.steps.length}`;

        // Highlight target element and scroll to it if needed
        if (step.target) {
            this.scrollToTarget(step.target, () => {
                this.highlightElement(step.target);
                this.positionPopover(step.target, step.position || 'bottom');
            });
        } else {
            this.clearHighlight();
            this.positionPopover(null, 'center');
        }

        // Show/hide Previous button
        const prevBtn = popover.querySelector('.btn-tutorial-prev');
        prevBtn.style.display = index > 0 ? 'inline-block' : 'none';

        // Update Next button text
        const nextBtn = popover.querySelector('.btn-tutorial-next');
        nextBtn.textContent = index === this.steps.length - 1 ? 'Finish' : 'Next';

        // Execute step action if defined
        if (step.action) {
            step.action();
        }
    }

    scrollToTarget(selector, callback) {
        // Resolve selector (handle :contains())
        let element;
        const containsMatch = selector.match(/^(.+):contains\(['"](.+)['"]\)$/);

        if (containsMatch) {
            const [, baseSelector, textContent] = containsMatch;
            const candidates = document.querySelectorAll(baseSelector);
            for (const candidate of candidates) {
                if (candidate.textContent.includes(textContent)) {
                    element = candidate;
                    break;
                }
            }
        } else {
            element = document.querySelector(selector);
        }

        if (!element) {
            callback();
            return;
        }

        const rect = element.getBoundingClientRect();
        const isVisible = (
            rect.top >= 0 &&
            rect.left >= 0 &&
            rect.bottom <= window.innerHeight &&
            rect.right <= window.innerWidth
        );

        if (!isVisible) {
            // Scroll element into view
            element.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'center' });
            // Wait for scroll animation, then position popover
            setTimeout(callback, 500);
        } else {
            // Already visible, proceed immediately
            callback();
        }
    }

    highlightElement(selector) {
        // Support text-matching pseudo-selector: .class:contains('text')
        let element;
        const containsMatch = selector.match(/^(.+):contains\(['"](.+)['"]\)$/);

        if (containsMatch) {
            const [, baseSelector, textContent] = containsMatch;
            const candidates = document.querySelectorAll(baseSelector);
            for (const candidate of candidates) {
                if (candidate.textContent.includes(textContent)) {
                    element = candidate;
                    break;
                }
            }
        } else {
            element = document.querySelector(selector);
        }

        if (!element) {
            console.warn('Tutorial target not found:', selector);
            this.clearHighlight();
            return;
        }

        const rect = element.getBoundingClientRect();
        const spotlight = this.overlay.querySelector('.tutorial-spotlight');
        const highlightBox = this.overlay.querySelector('.tutorial-highlight-box');
        const connector = this.overlay.querySelector('.tutorial-connector');

        const padding = 12;
        const left = rect.left - padding;
        const top = rect.top - padding;
        const right = rect.right + padding;
        const bottom = rect.bottom + padding;

        // Create cutout for highlighted element using clip-path
        spotlight.style.clipPath = `polygon(
            0% 0%, 0% 100%,
            ${left}px 100%,
            ${left}px ${top}px,
            ${right}px ${top}px,
            ${right}px ${bottom}px,
            ${left}px ${bottom}px,
            ${left}px 100%,
            100% 100%, 100% 0%
        )`;

        // Position highlight box around element
        highlightBox.style.display = 'block';
        highlightBox.style.left = `${left}px`;
        highlightBox.style.top = `${top}px`;
        highlightBox.style.width = `${right - left}px`;
        highlightBox.style.height = `${bottom - top}px`;

        // Store rect for connector drawing (after popover is positioned)
        this.highlightRect = { left, top, right, bottom };

        // Show connector
        connector.style.display = 'block';
    }

    clearHighlight() {
        const spotlight = this.overlay.querySelector('.tutorial-spotlight');
        const highlightBox = this.overlay.querySelector('.tutorial-highlight-box');
        const connector = this.overlay.querySelector('.tutorial-connector');

        spotlight.style.clipPath = 'none';
        highlightBox.style.display = 'none';
        connector.style.display = 'none';
        this.highlightRect = null;
    }

    drawConnector() {
        if (!this.highlightRect) return;

        const connector = this.overlay.querySelector('.tutorial-connector path');
        const popover = this.overlay.querySelector('.tutorial-popover');
        const popoverRect = popover.getBoundingClientRect();

        // Find closest edge of highlight box to popover
        const highlightCenter = {
            x: (this.highlightRect.left + this.highlightRect.right) / 2,
            y: (this.highlightRect.top + this.highlightRect.bottom) / 2
        };

        const popoverCenter = {
            x: popoverRect.left + popoverRect.width / 2,
            y: popoverRect.top + popoverRect.height / 2
        };

        // Determine connection points based on relative positions
        let startX, startY, endX, endY;

        // Popover connection point (closest edge)
        if (popoverCenter.y < highlightCenter.y) {
            // Popover is above highlight
            startX = popoverCenter.x;
            startY = popoverRect.bottom;
            endX = highlightCenter.x;
            endY = this.highlightRect.top;
        } else {
            // Popover is below highlight
            startX = popoverCenter.x;
            startY = popoverRect.top;
            endX = highlightCenter.x;
            endY = this.highlightRect.bottom;
        }

        // Create smooth curve
        const controlPointOffset = Math.abs(startY - endY) * 0.5;
        const path = `M ${startX} ${startY} C ${startX} ${startY + controlPointOffset}, ${endX} ${endY - controlPointOffset}, ${endX} ${endY}`;

        connector.setAttribute('d', path);
    }

    positionPopover(targetSelector, position) {
        const popover = this.overlay.querySelector('.tutorial-popover');

        if (!targetSelector || position === 'center') {
            popover.style.position = 'fixed';
            popover.style.top = '50%';
            popover.style.left = '50%';
            popover.style.transform = 'translate(-50%, -50%)';
            this.overlay.querySelector('.tutorial-connector').style.display = 'none';
            return;
        }

        const target = this._resolveTarget(targetSelector);
        if (!target) {
            this.positionPopover(null, 'center');
            return;
        }

        const margin = 10;
        const gap = 24;
        const stickyHeaderOffset = 60;

        popover.style.position = 'fixed';
        popover.style.transform = 'none';

        // Measure the actual popover so the fit checks aren't off by 100+px.
        const popoverRect = popover.getBoundingClientRect();
        const pw = popoverRect.width || 440;
        const ph = popoverRect.height || 280;

        const rect = target.getBoundingClientRect();
        const vw = window.innerWidth;
        const vh = window.innerHeight;
        const clamp = (v, lo, hi) => Math.max(lo, Math.min(v, hi));

        const fits = {
            bottom: rect.bottom + gap + ph <= vh - margin,
            top: rect.top - gap - ph >= stickyHeaderOffset + margin,
            right: rect.right + gap + pw <= vw - margin,
            left: rect.left - gap - pw >= margin,
        };

        // Preferred position first, then opposite vertical/horizontal, then sides.
        const chain = {
            bottom: ['bottom', 'top', 'right', 'left'],
            top: ['top', 'bottom', 'right', 'left'],
            right: ['right', 'left', 'bottom', 'top'],
            left: ['left', 'right', 'bottom', 'top'],
        }[position] || ['bottom', 'top', 'right', 'left'];

        const chosen = chain.find(c => fits[c]);

        if (!chosen) {
            // The target is taller than the viewport allows the popover to sit
            // alongside (typical for full-width section panels). Try to scroll
            // the target to the top once, then on retry pin the popover to the
            // viewport's bottom-right corner — a deterministic placement that
            // keeps the target's heading visible.
            if (!this._scrolledForFit) {
                this._scrolledForFit = true;
                const targetTopInDoc = rect.top + window.scrollY;
                window.scrollTo({
                    top: Math.max(0, targetTopInDoc - stickyHeaderOffset - margin),
                    behavior: 'smooth',
                });
                setTimeout(() => {
                    if (this.overlay && this.steps[this.currentStep]?.target === targetSelector) {
                        this.updatePositions();
                    }
                }, 350);
                return;
            }
            popover.style.top = `${vh - ph - margin}px`;
            popover.style.left = `${vw - pw - margin}px`;
            setTimeout(() => this.drawConnector(), 50);
            return;
        }
        this._scrolledForFit = false;

        let top, left;
        switch (chosen) {
            case 'bottom':
                top = rect.bottom + gap;
                left = clamp(rect.left, margin, vw - pw - margin);
                break;
            case 'top':
                top = rect.top - ph - gap;
                left = clamp(rect.left, margin, vw - pw - margin);
                break;
            case 'right':
                left = rect.right + gap;
                top = clamp(rect.top, stickyHeaderOffset + margin, vh - ph - margin);
                break;
            case 'left':
                left = rect.left - pw - gap;
                top = clamp(rect.top, stickyHeaderOffset + margin, vh - ph - margin);
                break;
        }

        popover.style.top = `${top}px`;
        popover.style.left = `${left}px`;

        setTimeout(() => this.drawConnector(), 50);
    }

    _resolveTarget(targetSelector) {
        const m = targetSelector.match(/^(.+):contains\(['"](.+)['"]\)$/);
        if (m) {
            for (const el of document.querySelectorAll(m[1])) {
                if (el.textContent.includes(m[2])) return el;
            }
            return null;
        }
        return document.querySelector(targetSelector);
    }

    bindEvents() {
        const close = this.overlay.querySelector('.tutorial-close-btn');
        const skip = this.overlay.querySelector('.btn-tutorial-skip');
        const prev = this.overlay.querySelector('.btn-tutorial-prev');
        const next = this.overlay.querySelector('.btn-tutorial-next');

        close.addEventListener('click', () => this.exit());
        skip.addEventListener('click', () => this.exit());
        prev.addEventListener('click', () => this.previousStep());
        next.addEventListener('click', () => this.nextStep());

        // ESC key to exit
        this.escapeHandler = (e) => {
            if (e.key === 'Escape' && this.overlay) {
                this.exit();
            }
        };
        document.addEventListener('keydown', this.escapeHandler);
    }

    nextStep() {
        if (this.currentStep < this.steps.length - 1) {
            this.currentStep++;
            this.showStep(this.currentStep);
        } else {
            this.complete();
        }
    }

    previousStep() {
        if (this.currentStep > 0) {
            this.currentStep--;
            this.showStep(this.currentStep);
        }
    }

    complete() {
        TutorialManager.markCompleted(this.id);
        this.exit();
        // Show success toast if available
        if (typeof window.showToast === 'function') {
            window.showToast(`Tutorial "${this.title}" completed!`, 'success');
        }
    }

    exit() {
        if (this.overlay) {
            this.overlay.remove();
            this.overlay = null;
        }
        if (this.escapeHandler) {
            document.removeEventListener('keydown', this.escapeHandler);
            this.escapeHandler = null;
        }
        if (this.scrollHandler) {
            window.removeEventListener('scroll', this.scrollHandler, true);
            this.scrollHandler = null;
        }
        if (this.resizeHandler) {
            window.removeEventListener('resize', this.resizeHandler);
            this.resizeHandler = null;
        }
    }
}

// Global function to start tutorial
window.startTutorial = async function(tutorialId) {
    try {
        const response = await fetch(`/static/tutorials/${tutorialId}.json`);
        if (!response.ok) {
            throw new Error(`Failed to load tutorial: ${response.status}`);
        }
        const definition = await response.json();
        const tutorial = new Tutorial(definition);
        tutorial.start();
    } catch (e) {
        console.error('Failed to load tutorial:', e);
        if (typeof window.showToast === 'function') {
            window.showToast('Failed to load tutorial', 'error');
        } else {
            alert('Failed to load tutorial. Please try again.');
        }
    }
};

// Export for global access
window.TutorialManager = TutorialManager;
