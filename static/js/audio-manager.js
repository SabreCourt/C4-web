(function () {
  class ArcadeMusicTrack {
    constructor(context, destination, config) {
      this.context = context;
      this.destination = destination;
      this.config = config || {};
      this.sequence = Array.isArray(this.config.sequence) && this.config.sequence.length
        ? this.config.sequence.slice()
        : [220, 247, 262, 294];
      this.tempo = this.config.tempo || 110;
      this.wave = this.config.wave || 'triangle';
      this.swing = typeof this.config.swing === 'number' ? this.config.swing : 0;
      this.stepIndex = 0;
      this.nextNoteTime = 0;
      this.running = false;
      this._raf = null;
      this.padOscillators = [];
      this.padGain = null;
    }

    start() {
      if (this.running) return;
      this.running = true;
      this.stepIndex = 0;
      this.nextNoteTime = this.context.currentTime + 0.12;
      if (Array.isArray(this.config.pad) && this.config.pad.length) {
        this._startPad();
      }
      this._schedule();
    }

    stop() {
      this.running = false;
      if (this._raf) {
        cancelAnimationFrame(this._raf);
        this._raf = null;
      }
      if (this.padGain) {
        const now = this.context.currentTime;
        this.padGain.gain.cancelScheduledValues(now);
        this.padGain.gain.setTargetAtTime(0.0001, now, 0.2);
        setTimeout(() => {
          this.padOscillators.forEach(osc => {
            try {
              osc.stop();
            } catch (error) {
              /* ignore */
            }
          });
          this.padOscillators = [];
          this.padGain.disconnect();
          this.padGain = null;
        }, 300);
      }
    }

    _startPad() {
      this.padGain = this.context.createGain();
      const padLevel = typeof this.config.padLevel === 'number' ? this.config.padLevel : 0.18;
      this.padGain.gain.setValueAtTime(0.0001, this.context.currentTime);
      this.padGain.connect(this.destination);
      const padWave = this.config.padWave || 'sine';
      this.padOscillators = this.config.pad.map(freq => {
        const osc = this.context.createOscillator();
        osc.type = padWave;
        osc.frequency.setValueAtTime(freq, this.context.currentTime);
        const subtleGain = this.context.createGain();
        subtleGain.gain.setValueAtTime(1, this.context.currentTime);
        osc.connect(subtleGain).connect(this.padGain);
        osc.start();
        return osc;
      });
      this.padGain.gain.linearRampToValueAtTime(padLevel, this.context.currentTime + 2.5);
    }

    _schedule() {
      if (!this.running) return;
      const lookAhead = 0.6;
      while (this.nextNoteTime < this.context.currentTime + lookAhead) {
        this._playStep(this.stepIndex, this.nextNoteTime);
        const beatDuration = 60 / this.tempo;
        const swingOffset = this.stepIndex % 2 === 1 ? this.swing * beatDuration : 0;
        this.nextNoteTime += beatDuration + swingOffset;
        this.stepIndex = (this.stepIndex + 1) % this.sequence.length;
      }
      this._raf = requestAnimationFrame(() => this._schedule());
    }

    _playStep(index, time) {
      const freq = this.sequence[index];
      if (!freq) return;
      const osc = this.context.createOscillator();
      osc.type = this.wave;
      osc.frequency.setValueAtTime(freq, time);

      const gain = this.context.createGain();
      const accent = this.config.accents && this.config.accents.includes(index) ? 1.4 : 1.0;
      const peak = (this.config.level || 0.22) * accent;
      gain.gain.setValueAtTime(0.0001, time);
      gain.gain.linearRampToValueAtTime(peak, time + 0.03);
      gain.gain.exponentialRampToValueAtTime(0.0001, time + (this.config.decay || 0.5));

      osc.connect(gain).connect(this.destination);
      osc.start(time);
      osc.stop(time + 1);
    }
  }

  class ArcadeAudioManager {
    constructor() {
      this.context = null;
      this.masterGain = null;
      this.musicGain = null;
      this.effectsGain = null;
      this.currentTrack = null;
      this.currentScene = null;
      this.sceneOptions = {};
      this.panel = null;
      this.backdrop = null;
      this.toggleButtons = [];
      this.musicSlider = null;
      this.effectsSlider = null;
      this.muteButton = null;
      this.panelOpen = false;
      this.musicVolume = this._loadVolume('music', 0.6);
      this.effectsVolume = this._loadVolume('effects', 0.8);
      this._unlockBound = this._unlockContext.bind(this);
      this._handleVisibility = this._handleVisibility.bind(this);
      this._createTrackPresets();
      this._attachUnlockListeners();
    }

    _createTrackPresets() {
      this.trackPresets = {
        menu: {
          sequence: [220, 247, 262, 330, 294, 247, 330, 370],
          tempo: 96,
          wave: 'triangle',
          level: 0.18,
          pad: [110, 165],
          padWave: 'sine',
          padLevel: 0.12
        },
        puissance4: {
          sequence: [196, 220, 247, 294, 247, 220, 196, 165],
          tempo: 104,
          wave: 'sawtooth',
          level: 0.2,
          pad: [147, 196],
          padWave: 'triangle',
          padLevel: 0.14
        },
        tetris: {
          sequence: [330, 392, 494, 523, 494, 392, 330, 392],
          tempo: 132,
          wave: 'square',
          level: 0.24,
          accents: [0, 4],
          swing: 0.04,
          pad: [196, 262],
          padWave: 'sine',
          padLevel: 0.1
        },
        pendu: {
          sequence: [262, 294, 330, 349, 330, 294, 262, 220],
          tempo: 82,
          wave: 'sine',
          level: 0.16,
          decay: 0.7,
          pad: [131, 196],
          padWave: 'sine',
          padLevel: 0.16
        },
        default: {
          sequence: [220, 247, 262, 294],
          tempo: 100,
          wave: 'triangle',
          level: 0.18
        }
      };
    }

    mount() {
      this.toggleButtons = Array.from(document.querySelectorAll('[data-sound-toggle]'));
      if (!this.toggleButtons.length) {
        return;
      }
      if (!this.panel) {
        this._createPanel();
      }
      this.toggleButtons.forEach(button => {
        button.setAttribute('aria-haspopup', 'dialog');
        button.setAttribute('aria-expanded', this.panelOpen ? 'true' : 'false');
        button.addEventListener('click', () => {
          this._ensureContext();
          this.togglePanel();
        });
      });
      this._updateToggleState();
    }

    setScene(name, options = {}) {
      this.currentScene = name;
      this.sceneOptions = options || {};
      if (this.context && this.context.state === 'running') {
        this._startMusic();
      }
    }

    playEffect(effect, options = {}) {
      if (!this.effectsVolume) return;
      const ctx = this._ensureContext();
      if (!ctx || ctx.state !== 'running') return;
      const now = ctx.currentTime;
      switch (effect) {
        case 'tokenDrop':
          this._percussionHit(now, options.variant || 0);
          break;
        case 'lineClear':
          this._lineClear(now, options.count || 1);
          break;
        case 'pieceLand':
          this._pieceLand(now, options.hardDrop);
          break;
        case 'victory':
          this._victoryFanfares(now);
          break;
        case 'defeat':
          this._defeatTone(now);
          break;
        case 'menuSelect':
          this._menuSelect(now);
          break;
        default:
          break;
      }
    }

    togglePanel(force) {
      const open = typeof force === 'boolean' ? force : !this.panelOpen;
      if (!this.panel || !this.backdrop) return;
      this.panelOpen = open;
      this.panel.classList.toggle('is-open', open);
      this.backdrop.classList.toggle('is-visible', open);
      this._updateToggleState();
      if (open) {
        this.panel.focus();
      }
    }

    _createPanel() {
      this.backdrop = document.createElement('div');
      this.backdrop.className = 'sound-panel-backdrop';
      this.backdrop.addEventListener('click', () => this.togglePanel(false));

      this.panel = document.createElement('div');
      this.panel.className = 'sound-panel neo-glass';
      this.panel.setAttribute('role', 'dialog');
      this.panel.setAttribute('aria-modal', 'true');
      this.panel.setAttribute('aria-label', 'Réglages audio');
      this.panel.tabIndex = -1;
      this.panel.innerHTML = `
        <header class="sound-panel__header">
          <div>
            <p class="sound-panel__eyebrow">Ambiance</p>
            <h2 class="sound-panel__title">Réglages audio</h2>
          </div>
          <button type="button" class="sound-panel__close" aria-label="Fermer les réglages audio">✕</button>
        </header>
        <div class="sound-panel__body">
          <label class="sound-panel__control">
            <span class="sound-panel__label">Volume de la musique</span>
            <input type="range" min="0" max="100" value="${Math.round(this.musicVolume * 100)}" class="sound-panel__slider" data-sound="music" />
          </label>
          <label class="sound-panel__control">
            <span class="sound-panel__label">Volume des effets</span>
            <input type="range" min="0" max="100" value="${Math.round(this.effectsVolume * 100)}" class="sound-panel__slider" data-sound="effects" />
          </label>
          <button type="button" class="neo-button tertiary sound-panel__mute">${this._isMuted() ? '🔈 Réactiver' : '🔇 Couper le son'}</button>
        </div>
      `;

      document.body.appendChild(this.backdrop);
      document.body.appendChild(this.panel);

      const closeButton = this.panel.querySelector('.sound-panel__close');
      if (closeButton) {
        closeButton.addEventListener('click', () => this.togglePanel(false));
      }

      this.musicSlider = this.panel.querySelector('input[data-sound="music"]');
      this.effectsSlider = this.panel.querySelector('input[data-sound="effects"]');
      this.muteButton = this.panel.querySelector('.sound-panel__mute');

      if (this.musicSlider) {
        this.musicSlider.addEventListener('input', event => {
          const value = Number(event.target.value) / 100;
          this.setMusicVolume(value);
        });
      }
      if (this.effectsSlider) {
        this.effectsSlider.addEventListener('input', event => {
          const value = Number(event.target.value) / 100;
          this.setEffectsVolume(value);
        });
      }
      if (this.muteButton) {
        this.muteButton.addEventListener('click', () => {
          if (this._isMuted()) {
            this.setMusicVolume(this._loadVolume('music', 0.6) || 0.6, false);
            this.setEffectsVolume(this._loadVolume('effects', 0.8) || 0.8, false);
          } else {
            this._storeVolume('music', this.musicVolume);
            this._storeVolume('effects', this.effectsVolume);
            this.setMusicVolume(0, false);
            this.setEffectsVolume(0, false);
          }
          if (this.muteButton) {
            this.muteButton.textContent = this._isMuted() ? '🔈 Réactiver' : '🔇 Couper le son';
          }
          if (this.musicSlider) {
            this.musicSlider.value = Math.round(this.musicVolume * 100);
          }
          if (this.effectsSlider) {
            this.effectsSlider.value = Math.round(this.effectsVolume * 100);
          }
          this._updateToggleState();
        });
      }

      document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && this.panelOpen) {
          this.togglePanel(false);
        }
      });
    }

    setMusicVolume(value, store = true) {
      const clamped = Math.max(0, Math.min(1, value));
      this.musicVolume = clamped;
      if (store) {
        localStorage.setItem('arcade_audio_music', String(clamped));
      }
      if (this.musicGain) {
        const now = this.context.currentTime;
        const scaled = clamped * clamped;
        this.musicGain.gain.cancelScheduledValues(now);
        this.musicGain.gain.setTargetAtTime(scaled, now, 0.08);
      }
      this._updateToggleState();
    }

    setEffectsVolume(value, store = true) {
      const clamped = Math.max(0, Math.min(1, value));
      this.effectsVolume = clamped;
      if (store) {
        localStorage.setItem('arcade_audio_effects', String(clamped));
      }
      if (this.effectsGain) {
        const now = this.context.currentTime;
        const scaled = clamped * clamped;
        this.effectsGain.gain.cancelScheduledValues(now);
        this.effectsGain.gain.setTargetAtTime(scaled, now, 0.04);
      }
      this._updateToggleState();
    }

    _updateToggleState() {
      const icon = this._isMuted() ? '🔈' : '🔊';
      this.toggleButtons.forEach(button => {
        const label = button.dataset.defaultLabel || button.textContent || 'Ambiance';
        if (!button.dataset.defaultLabel) {
          button.dataset.defaultLabel = label.replace(/^🔊|🔈|🔇\s*/, '').trim();
        }
        button.textContent = `${icon} ${button.dataset.defaultLabel}`;
        button.setAttribute('aria-expanded', this.panelOpen ? 'true' : 'false');
      });
    }

    _isMuted() {
      return this.musicVolume === 0 && this.effectsVolume === 0;
    }

    _startMusic() {
      const preset = this.trackPresets[this.currentScene] || this.trackPresets.default;
      if (!preset) return;
      if (!this.context || this.context.state !== 'running') {
        return;
      }
      if (this.currentTrack) {
        this.currentTrack.stop();
        this.currentTrack = null;
      }
      const config = Object.assign({}, preset, this.sceneOptions || {});
      this.currentTrack = new ArcadeMusicTrack(this.context, this.musicGain, config);
      this.currentTrack.start();
    }

    _ensureContext() {
      if (typeof window === 'undefined') return null;
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (!AudioContext) return null;
      if (!this.context) {
        this.context = new AudioContext();
        this.masterGain = this.context.createGain();
        this.musicGain = this.context.createGain();
        this.effectsGain = this.context.createGain();

        this.masterGain.connect(this.context.destination);
        this.musicGain.connect(this.masterGain);
        this.effectsGain.connect(this.masterGain);

        const now = this.context.currentTime;
        this.masterGain.gain.setValueAtTime(1, now);
        this.musicGain.gain.setValueAtTime(this.musicVolume * this.musicVolume, now);
        this.effectsGain.gain.setValueAtTime(this.effectsVolume * this.effectsVolume, now);

        document.addEventListener('visibilitychange', this._handleVisibility);
      }
      if (this.context.state === 'suspended') {
        this.context.resume().then(() => {
          if (this.currentScene) {
            this._startMusic();
          }
        }).catch(() => {
          /* ignore */
        });
      } else if (this.currentScene && !this.currentTrack) {
        this._startMusic();
      }
      return this.context;
    }

    _handleVisibility() {
      if (!this.context) return;
      if (document.hidden) {
        this.masterGain.gain.setTargetAtTime(0.0001, this.context.currentTime, 0.12);
      } else {
        this.masterGain.gain.setTargetAtTime(1, this.context.currentTime, 0.2);
      }
    }

    _attachUnlockListeners() {
      const unlock = () => this._unlockContext();
      ['pointerdown', 'touchstart', 'keydown'].forEach(eventName => {
        document.addEventListener(eventName, unlock, { once: true, passive: true });
      });
    }

    _unlockContext() {
      const ctx = this._ensureContext();
      if (ctx && ctx.state === 'running' && this.currentScene) {
        this._startMusic();
      }
    }

    _loadVolume(type, fallback) {
      try {
        const value = localStorage.getItem(`arcade_audio_${type}`);
        if (value !== null) {
          const parsed = parseFloat(value);
          if (!Number.isNaN(parsed)) {
            return Math.max(0, Math.min(1, parsed));
          }
        }
      } catch (error) {
        /* ignore */
      }
      return fallback;
    }

    _storeVolume(type, value) {
      try {
        localStorage.setItem(`arcade_audio_${type}`, String(Math.max(0, Math.min(1, value))));
      } catch (error) {
        /* ignore */
      }
    }

    _percussionHit(time, variant = 0) {
      const osc = this.context.createOscillator();
      const gain = this.context.createGain();
      const startFreq = variant > 0 ? 340 : 280;
      const endFreq = variant > 0 ? 160 : 120;
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(startFreq, time);
      osc.frequency.exponentialRampToValueAtTime(endFreq, time + 0.18);
      gain.gain.setValueAtTime(0.001, time);
      gain.gain.linearRampToValueAtTime(0.38, time + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.001, time + 0.26);
      osc.connect(gain).connect(this.effectsGain);
      osc.start(time);
      osc.stop(time + 0.3);

      const noiseBuffer = this.context.createBuffer(1, this.context.sampleRate * 0.12, this.context.sampleRate);
      const data = noiseBuffer.getChannelData(0);
      for (let i = 0; i < data.length; i += 1) {
        const decay = 1 - i / data.length;
        data[i] = (Math.random() * 2 - 1) * decay * 0.6;
      }
      const noise = this.context.createBufferSource();
      noise.buffer = noiseBuffer;
      const noiseGain = this.context.createGain();
      noiseGain.gain.setValueAtTime(0.12, time);
      noiseGain.gain.exponentialRampToValueAtTime(0.001, time + 0.18);
      noise.connect(noiseGain).connect(this.effectsGain);
      noise.start(time);
      noise.stop(time + 0.22);
    }

    _lineClear(time, count) {
      const baseFreq = 420;
      for (let i = 0; i < count; i += 1) {
        this._playNote(baseFreq + i * 90, time + i * 0.06, 0.2, 'square', 0.22);
      }
      this._noiseSweep(time + 0.04, 0.18);
    }

    _pieceLand(time, hardDrop = false) {
      const freq = hardDrop ? 200 : 150;
      this._playNote(freq, time, 0.18, 'triangle', hardDrop ? 0.24 : 0.18);
    }

    _victoryFanfares(time) {
      const notes = [523.25, 659.25, 783.99, 1046.5];
      notes.forEach((freq, index) => {
        this._playNote(freq, time + index * 0.18, 0.32, 'sine', 0.32);
      });
      this._playNote(987.77, time + 0.54, 0.5, 'triangle', 0.22);
    }

    _defeatTone(time) {
      this._playNote(196, time, 0.6, 'sine', 0.2);
      this._playNote(155, time + 0.22, 0.6, 'sawtooth', 0.15);
    }

    _menuSelect(time) {
      this._playNote(392, time, 0.12, 'sine', 0.18);
    }

    _noiseSweep(time, duration) {
      const noiseBuffer = this.context.createBuffer(1, this.context.sampleRate * duration, this.context.sampleRate);
      const data = noiseBuffer.getChannelData(0);
      for (let i = 0; i < data.length; i += 1) {
        const t = i / data.length;
        data[i] = (Math.random() * 2 - 1) * (1 - t);
      }
      const noise = this.context.createBufferSource();
      noise.buffer = noiseBuffer;
      const filter = this.context.createBiquadFilter();
      filter.type = 'highpass';
      filter.frequency.setValueAtTime(300, time);
      filter.frequency.linearRampToValueAtTime(1800, time + duration);
      const gain = this.context.createGain();
      gain.gain.setValueAtTime(0.001, time);
      gain.gain.linearRampToValueAtTime(0.22, time + 0.04);
      gain.gain.exponentialRampToValueAtTime(0.001, time + duration);
      noise.connect(filter).connect(gain).connect(this.effectsGain);
      noise.start(time);
      noise.stop(time + duration + 0.02);
    }

    _playNote(frequency, offset, duration, wave = 'sine', level = 0.24) {
      const ctx = this.context;
      if (!ctx) return;
      const startTime = ctx.currentTime + (offset || 0);
      const osc = ctx.createOscillator();
      osc.type = wave;
      osc.frequency.setValueAtTime(frequency, startTime);
      const gain = ctx.createGain();
      const peak = level * (this.effectsVolume || 1);
      gain.gain.setValueAtTime(0.001, startTime);
      gain.gain.linearRampToValueAtTime(peak, startTime + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.001, startTime + (duration || 0.3));
      osc.connect(gain).connect(this.effectsGain);
      osc.start(startTime);
      osc.stop(startTime + (duration || 0.3) + 0.05);
    }
  }

  const manager = new ArcadeAudioManager();
  window.arcadeAudio = manager;
  document.addEventListener('DOMContentLoaded', () => manager.mount());
})();
