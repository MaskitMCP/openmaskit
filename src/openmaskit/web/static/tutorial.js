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
            // Center popover
            popover.style.position = 'fixed';
            popover.style.top = '50%';
            popover.style.left = '50%';
            popover.style.transform = 'translate(-50%, -50%)';

            // Clear connector when centered
            const connector = this.overlay.querySelector('.tutorial-connector');
            connector.style.display = 'none';
            return;
        }

        // Support text-matching pseudo-selector (same as highlightElement)
        let target;
        const containsMatch = targetSelector.match(/^(.+):contains\(['"](.+)['"]\)$/);

        if (containsMatch) {
            const [, baseSelector, textContent] = containsMatch;
            const candidates = document.querySelectorAll(baseSelector);
            for (const candidate of candidates) {
                if (candidate.textContent.includes(textContent)) {
                    target = candidate;
                    break;
                }
            }
        } else {
            target = document.querySelector(targetSelector);
        }

        if (!target) {
            // Fallback to center if target not found
            this.positionPopover(null, 'center');
            return;
        }

        const rect = target.getBoundingClientRect();
        const popoverWidth = 440;
        const popoverHeight = 300; // Increased estimate for safety
        const gap = 55; // Increased gap to prevent overlap with highlighted elements
        const margin = 10; // Margin from viewport edges

        popover.style.position = 'fixed';
        popover.style.transform = 'none';

        let top, left;
        let finalPosition = position;

        // Smart positioning: try requested position first, fallback if doesn't fit
        switch (position) {
            case 'bottom':
                top = rect.bottom + gap;
                // If popover would go below viewport, try above
                if (top + popoverHeight > window.innerHeight - margin) {
                    top = rect.top - popoverHeight - gap;
                    finalPosition = 'top';
                    // If still doesn't fit, center it vertically
                    if (top < margin) {
                        top = Math.max(margin, (window.innerHeight - popoverHeight) / 2);
                        finalPosition = 'center-vertical';
                    }
                }
                left = Math.max(margin, Math.min(rect.left, window.innerWidth - popoverWidth - margin));
                break;

            case 'top':
                top = rect.top - popoverHeight - gap;
                // If popover would go above viewport, try below
                if (top < margin) {
                    top = rect.bottom + gap;
                    finalPosition = 'bottom';
                    // If still doesn't fit, center it vertically
                    if (top + popoverHeight > window.innerHeight - margin) {
                        top = Math.max(margin, (window.innerHeight - popoverHeight) / 2);
                        finalPosition = 'center-vertical';
                    }
                }
                left = Math.max(margin, Math.min(rect.left, window.innerWidth - popoverWidth - margin));
                break;

            case 'right':
                left = rect.right + gap;
                // If popover would go off right edge, try left
                if (left + popoverWidth > window.innerWidth - margin) {
                    left = rect.left - popoverWidth - gap;
                    finalPosition = 'left';
                    // If still doesn't fit, center horizontally
                    if (left < margin) {
                        left = Math.max(margin, (window.innerWidth - popoverWidth) / 2);
                    }
                }
                top = Math.max(margin, Math.min(rect.top, window.innerHeight - popoverHeight - margin));
                break;

            case 'left':
                left = rect.left - popoverWidth - gap;
                // If popover would go off left edge, try right
                if (left < margin) {
                    left = rect.right + gap;
                    finalPosition = 'right';
                    // If still doesn't fit, center horizontally
                    if (left + popoverWidth > window.innerWidth - margin) {
                        left = Math.max(margin, (window.innerWidth - popoverWidth) / 2);
                    }
                }
                top = Math.max(margin, Math.min(rect.top, window.innerHeight - popoverHeight - margin));
                break;

            default:
                // Default to center
                this.positionPopover(null, 'center');
                return;
        }

        popover.style.top = `${top}px`;
        popover.style.left = `${left}px`;

        // Scroll target into view if it's partially off-screen
        if (rect.top < 0 || rect.bottom > window.innerHeight ||
            rect.left < 0 || rect.right > window.innerWidth) {
            target.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'center' });
            // Recalculate after scroll animation
            setTimeout(() => {
                if (this.overlay && this.steps[this.currentStep]?.target === targetSelector) {
                    this.updatePositions();
                }
            }, 500);
        }

        // Draw connector line after positioning
        setTimeout(() => this.drawConnector(), 50);
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
