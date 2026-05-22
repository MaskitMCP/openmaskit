/**
 * Tutorial System for Maskit
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

        // Highlight target element
        if (step.target) {
            this.highlightElement(step.target);
            this.positionPopover(step.target, step.position || 'bottom');
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

    highlightElement(selector) {
        const element = document.querySelector(selector);
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

        const target = document.querySelector(targetSelector);
        if (!target) {
            // Fallback to center if target not found
            this.positionPopover(null, 'center');
            return;
        }

        const rect = target.getBoundingClientRect();
        const popoverWidth = 440;
        const popoverHeight = 250; // estimated
        const gap = 32;

        popover.style.position = 'fixed';
        popover.style.transform = 'none';

        switch (position) {
            case 'bottom':
                popover.style.top = `${rect.bottom + gap}px`;
                popover.style.left = `${Math.max(20, Math.min(rect.left, window.innerWidth - popoverWidth - 20))}px`;
                break;
            case 'top':
                popover.style.top = `${Math.max(20, rect.top - popoverHeight - gap)}px`;
                popover.style.left = `${Math.max(20, Math.min(rect.left, window.innerWidth - popoverWidth - 20))}px`;
                break;
            case 'right':
                popover.style.top = `${Math.max(20, Math.min(rect.top, window.innerHeight - popoverHeight - 20))}px`;
                popover.style.left = `${Math.min(rect.right + gap, window.innerWidth - popoverWidth - 20)}px`;
                break;
            case 'left':
                popover.style.top = `${Math.max(20, Math.min(rect.top, window.innerHeight - popoverHeight - 20))}px`;
                popover.style.left = `${Math.max(20, rect.left - popoverWidth - gap)}px`;
                break;
            default:
                // Default to center
                this.positionPopover(null, 'center');
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
