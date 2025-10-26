(function () {
  'use strict';

  const body = document.body;
  const pseudo = body ? body.dataset.pseudo || '' : '';

  const portal = document.getElementById('portal');
  const navRoot = document.querySelector('[data-nav-root]');
  const navItems = document.querySelectorAll('[data-nav-item]');
  const dropdownWrappers = document.querySelectorAll('[data-dropdown]');
  const dropdownTriggers = document.querySelectorAll('[data-dropdown-trigger]');
  const dropdownLinks = document.querySelectorAll('[data-game-link]');
  const friendsButton = document.querySelector('[data-action="friends"]');
  const navBadge = document.querySelector('[data-friends-unread]');
  const contactPanel = document.getElementById('contact-panel');
  const contactClose = contactPanel ? contactPanel.querySelector('.contact-panel__close') : null;
  const contactList = document.getElementById('contact-list');
  const contactSearch = document.getElementById('contact-search');
  const contactEmpty = document.getElementById('contact-empty-state');
  const contactThread = document.getElementById('contact-thread');
  const conversationClose = contactThread ? contactThread.querySelector('.conversation__close') : null;
  const conversationMessages = document.getElementById('conversation-messages');
  const conversationForm = document.getElementById('conversation-form');
  const conversationInput = document.getElementById('conversation-input');
  const conversationSubmit = conversationForm ? conversationForm.querySelector('button[type="submit"]') : null;
  const conversationContact = document.getElementById('conversation-contact');
  const conversationStatus = document.getElementById('conversation-status');

  const state = {
    contacts: new Map(),
    contactsLoaded: false,
    selected: null,
    renderedMessages: new Set(),
    unreadTotal: 0,
  };

  let socket;
  let loadingContacts = false;
  const pendingRead = new Set();

  document.addEventListener('DOMContentLoaded', () => {
    initPortalLinks();
    initAudioScene();
    initNavigation();
    initContacts();
  });

  function initPortalLinks() {
    if (!portal) {
      return;
    }

    const navigateWithPortal = url => {
      portal.classList.add('is-active');
      setTimeout(() => {
        window.location.assign(url);
      }, 360);
    };

    document.querySelectorAll('.nav-item[href], [data-portal-link]').forEach(link => {
      link.addEventListener('click', event => {
        if (
          event.defaultPrevented ||
          event.metaKey ||
          event.ctrlKey ||
          event.shiftKey ||
          event.button !== 0
        ) {
          return;
        }
        const target = link.getAttribute('href');
        if (!target || target.startsWith('#')) {
          return;
        }
        const sameLocation =
          link.origin === window.location.origin &&
          link.pathname === window.location.pathname &&
          link.search === window.location.search &&
          (!link.hash || link.hash === '#');
        if (sameLocation) {
          return;
        }
        event.preventDefault();
        navigateWithPortal(link.href);
      });
    });
  }

  function initAudioScene() {
    if (!window.arcadeAudio || !body) {
      return;
    }
    const scene = body.dataset.scene || 'menu';
    window.arcadeAudio.setScene(scene);
    const interactive = document.querySelectorAll('.neo-button, .nav-item, .nav-dropdown__link');
    const playHover = () => window.arcadeAudio.playEffect('menuSelect');
    interactive.forEach(element => {
      element.addEventListener('mouseenter', playHover);
      element.addEventListener('focus', playHover);
    });
  }

  function initNavigation() {
    setActiveNavItem();
    initDropdowns();
  }

  function setActiveNavItem() {
    if (!body) {
      return;
    }
    const page = body.dataset.page || '';
    navItems.forEach(item => {
      const matches = item.dataset.navItem === page;
      item.classList.toggle('is-active', matches);
      if (matches) {
        item.setAttribute('aria-current', 'page');
      } else {
        item.removeAttribute('aria-current');
      }
    });
    dropdownTriggers.forEach(trigger => {
      trigger.classList.remove('is-active');
      trigger.removeAttribute('aria-current');
    });
    dropdownLinks.forEach(link => {
      const matches = link.dataset.gameLink === page;
      link.classList.toggle('is-active', matches);
      if (matches) {
        link.setAttribute('aria-current', 'page');
        const wrapper = link.closest('[data-dropdown]');
        if (wrapper) {
          const trigger = wrapper.querySelector('[data-dropdown-trigger]');
          if (trigger) {
            trigger.classList.add('is-active');
            trigger.setAttribute('aria-current', 'page');
          }
        }
      } else {
        link.removeAttribute('aria-current');
      }
    });
  }

  function initDropdowns() {
    if (!dropdownWrappers.length) {
      return;
    }

    const closeDropdown = wrapper => {
      if (!wrapper) {
        return;
      }
      wrapper.classList.remove('is-open');
      const trigger = wrapper.querySelector('[data-dropdown-trigger]');
      const menu = wrapper.querySelector('[data-dropdown-menu]');
      if (trigger) {
        trigger.setAttribute('aria-expanded', 'false');
      }
      if (menu && !menu.hasAttribute('hidden')) {
        menu.setAttribute('hidden', '');
      }
    };

    const openDropdown = wrapper => {
      if (!wrapper) {
        return;
      }
      dropdownWrappers.forEach(other => {
        if (other !== wrapper) {
          closeDropdown(other);
        }
      });
      wrapper.classList.add('is-open');
      const trigger = wrapper.querySelector('[data-dropdown-trigger]');
      const menu = wrapper.querySelector('[data-dropdown-menu]');
      if (trigger) {
        trigger.setAttribute('aria-expanded', 'true');
      }
      if (menu) {
        menu.removeAttribute('hidden');
      }
    };

    dropdownWrappers.forEach(wrapper => {
      const trigger = wrapper.querySelector('[data-dropdown-trigger]');
      const menu = wrapper.querySelector('[data-dropdown-menu]');
      if (!trigger || !menu) {
        return;
      }

      trigger.addEventListener('click', event => {
        event.preventDefault();
        if (wrapper.classList.contains('is-open')) {
          closeDropdown(wrapper);
        } else {
          openDropdown(wrapper);
        }
      });

      trigger.addEventListener('keydown', event => {
        if (event.key === 'ArrowDown') {
          event.preventDefault();
          openDropdown(wrapper);
          const firstLink = menu.querySelector('.nav-dropdown__link');
          if (firstLink) {
            firstLink.focus();
          }
        } else if (event.key === 'Escape') {
          closeDropdown(wrapper);
        }
      });

      menu.addEventListener('keydown', event => {
        if (event.key === 'Escape') {
          closeDropdown(wrapper);
          if (trigger) {
            trigger.focus();
          }
        }
      });

      menu.querySelectorAll('.nav-dropdown__link').forEach(link => {
        link.addEventListener('click', () => {
          closeDropdown(wrapper);
        });
      });
    });

    document.addEventListener('click', event => {
      const target = event.target;
      if (!target) {
        return;
      }
      if (!target.closest('[data-dropdown]')) {
        dropdownWrappers.forEach(closeDropdown);
      }
    });

    document.addEventListener('keydown', event => {
      if (event.key === 'Escape') {
        dropdownWrappers.forEach(closeDropdown);
      }
    });
  }

  function initContacts() {
    if (!friendsButton || !contactPanel) {
      return;
    }

    friendsButton.setAttribute('aria-expanded', 'false');
    friendsButton.addEventListener('click', () => toggleContactPanel());
    if (contactClose) {
      contactClose.addEventListener('click', () => toggleContactPanel(false));
    }
    if (conversationClose) {
      conversationClose.addEventListener('click', closeConversation);
    }
    if (contactPanel) {
      contactPanel.addEventListener('keydown', event => {
        if (event.key === 'Escape') {
          toggleContactPanel(false);
        }
      });
    }
    if (contactSearch) {
      contactSearch.addEventListener('input', handleSearch);
    }
    if (conversationForm) {
      conversationForm.addEventListener('submit', handleConversationSubmit);
    }

    setupSocket();
    loadContacts();
  }

  function setupSocket() {
    if (typeof io !== 'function') {
      return;
    }

    socket = io();
    socket.on('connect', () => {
      if (pseudo) {
        socket.emit('pseudo', pseudo);
      }
    });

    socket.on('demande_pseudo', () => {
      if (pseudo) {
        socket.emit('pseudo', pseudo);
      }
    });

    socket.on('presence_update', payload => {
      const name = payload && payload.pseudo;
      if (!name || name === pseudo) {
        return;
      }
      ensureContact(name);
      setContactOnline(name, Boolean(payload.online));
      if (state.selected === name) {
        updateConversationHeader(state.contacts.get(name));
      }
      renderContactList();
    });

    socket.on('private_message', message => {
      if (!message || !message.id) {
        return;
      }
      const other = message.from === pseudo ? message.to : message.from;
      const incoming = message.to === pseudo;
      if (!other || other === pseudo) {
        return;
      }
      ensureContact(other);
      if (incoming && state.selected === other && isPanelOpen()) {
        appendMessage(message, 'incoming');
        setContactUnread(other, 0);
        markConversationRead(other);
        updateConversationHeader(state.contacts.get(other));
      } else if (incoming) {
        setContactUnread(other, (state.contacts.get(other)?.unread_count || 0) + 1);
      } else if (state.selected === other) {
        appendMessage(message, 'outgoing');
      }
      renderContactList();
    });
  }

  function toggleContactPanel(force) {
    if (!contactPanel || !friendsButton) {
      return;
    }
    const open = typeof force === 'boolean' ? force : !contactPanel.classList.contains('is-open');
    contactPanel.classList.toggle('is-open', open);
    contactPanel.setAttribute('aria-hidden', open ? 'false' : 'true');
    friendsButton.setAttribute('aria-expanded', open ? 'true' : 'false');

    if (open) {
      if (!state.contactsLoaded && !loadingContacts) {
        loadContacts();
      }
      requestAnimationFrame(() => {
        if (contactSearch) {
          contactSearch.focus();
        } else {
          contactPanel.focus();
        }
      });
    } else {
      if (contactSearch) {
        contactSearch.value = '';
      }
      handleSearch();
      if (friendsButton) {
        friendsButton.focus();
      }
    }
  }

  function isPanelOpen() {
    return contactPanel ? contactPanel.classList.contains('is-open') : false;
  }

  async function loadContacts() {
    if (loadingContacts) {
      return;
    }
    loadingContacts = true;
    try {
      const response = await fetch('/contacts/list', {
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) {
        throw new Error('contacts_load_failed');
      }
      const payload = await response.json();
      state.contacts.clear();
      const list = Array.isArray(payload.contacts) ? payload.contacts : [];
      list.forEach(item => {
        if (!item || !item.pseudo || item.pseudo === pseudo) {
          return;
        }
        state.contacts.set(item.pseudo, {
          pseudo: item.pseudo,
          online: Boolean(item.online),
          unread_count: Number(item.unread_count) || 0,
        });
      });
      state.contactsLoaded = true;
      updateUnreadBadge();
      renderContactList();
    } catch (error) {
      console.error('contacts_list', error);
      if (contactList) {
        contactList.innerHTML = '<li class="contact-panel__list-empty">Impossible de charger les contacts pour le moment.</li>';
      }
    } finally {
      loadingContacts = false;
    }
  }

  function ensureContact(name) {
    if (!name || name === pseudo) {
      return;
    }
    if (!state.contacts.has(name)) {
      state.contacts.set(name, { pseudo: name, online: false, unread_count: 0 });
    }
  }

  function setContactOnline(name, online) {
    const contact = state.contacts.get(name);
    if (!contact) {
      return;
    }
    contact.online = online;
    if (state.selected === name) {
      updateConversationHeader(contact);
    }
  }

  function setContactUnread(name, count) {
    const contact = state.contacts.get(name);
    if (!contact) {
      return;
    }
    const value = Math.max(0, Number(count) || 0);
    contact.unread_count = value;
    updateUnreadBadge();
  }

  function updateUnreadBadge() {
    const total = Array.from(state.contacts.values()).reduce((sum, contact) => sum + (contact.unread_count || 0), 0);
    state.unreadTotal = total;
    if (!navBadge) {
      return;
    }
    if (total > 0) {
      navBadge.hidden = false;
      navBadge.textContent = total > 99 ? '99+' : String(total);
    } else {
      navBadge.hidden = true;
    }
  }

  function renderContactList() {
    if (!contactList) {
      return;
    }
    contactList.innerHTML = '';
    const contacts = Array.from(state.contacts.values());
    if (contacts.length === 0) {
      const empty = document.createElement('li');
      empty.className = 'contact-panel__list-empty';
      empty.textContent = 'Invite tes amis pour commencer une conversation.';
      contactList.appendChild(empty);
      return;
    }
    contacts.sort((a, b) => {
      const onlineDiff = Number(b.online) - Number(a.online);
      if (onlineDiff !== 0) {
        return onlineDiff;
      }
      const unreadDiff = (b.unread_count || 0) - (a.unread_count || 0);
      if (unreadDiff !== 0) {
        return unreadDiff;
      }
      return a.pseudo.localeCompare(b.pseudo, 'fr', { sensitivity: 'base' });
    });

    contacts.forEach(contact => {
      const item = document.createElement('li');
      item.className = 'contact-item';
      item.dataset.pseudo = contact.pseudo;
      if (state.selected === contact.pseudo) {
        item.classList.add('is-active');
      }

      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'contact-item__button';
      button.dataset.pseudo = contact.pseudo;

      const presence = document.createElement('span');
      presence.className = 'contact-item__presence' + (contact.online ? ' contact-item__presence--online' : '');
      const name = document.createElement('span');
      name.className = 'contact-item__name';
      name.textContent = contact.pseudo;

      button.append(presence, name);

      if (contact.unread_count > 0) {
        const badge = document.createElement('span');
        badge.className = 'contact-item__badge';
        badge.textContent = contact.unread_count > 99 ? '99+' : String(contact.unread_count);
        button.appendChild(badge);
      }

      button.addEventListener('click', () => {
        if (state.selected === contact.pseudo && isPanelOpen()) {
          return;
        }
        openConversation(contact.pseudo);
        if (!isPanelOpen()) {
          toggleContactPanel(true);
        }
      });

      item.appendChild(button);
      contactList.appendChild(item);
    });

    handleSearch();
  }

  function handleSearch(event) {
    if (!contactList) {
      return;
    }
    const query = (event && event.target ? event.target.value : contactSearch ? contactSearch.value : '')
      .trim()
      .toLowerCase();
    const items = contactList.querySelectorAll('.contact-item');
    let visible = 0;
    items.forEach(item => {
      const name = (item.dataset.pseudo || '').toLowerCase();
      const matches = !query || name.includes(query);
      item.classList.toggle('hidden', !matches);
      if (matches) {
        visible += 1;
      }
    });

    let empty = contactList.querySelector('[data-search-empty]');
    if (query && visible === 0) {
      if (!empty) {
        empty = document.createElement('li');
        empty.dataset.searchEmpty = 'true';
        empty.className = 'contact-panel__list-empty';
        empty.textContent = 'Aucun joueur ne correspond à ta recherche.';
        contactList.appendChild(empty);
      }
    } else if (empty) {
      empty.remove();
    }
  }

  function clearConversation() {
    if (conversationMessages) {
      conversationMessages.innerHTML = '';
    }
    state.renderedMessages.clear();
  }

  function closeConversation() {
    state.selected = null;
    if (contactThread) {
      contactThread.classList.add('hidden');
      contactThread.setAttribute('data-current-contact', '');
    }
    if (contactEmpty) {
      contactEmpty.classList.remove('hidden');
    }
    clearConversation();
    renderContactList();
  }

  async function openConversation(target) {
    if (!target) {
      return;
    }
    try {
      const response = await fetch(`/contacts/conversation/${encodeURIComponent(target)}`, {
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) {
        throw new Error('conversation_load_failed');
      }
      const payload = await response.json();
      const contactInfo = payload.contact || { pseudo: target };
      ensureContact(contactInfo.pseudo);
      const entry = state.contacts.get(contactInfo.pseudo);
      if (entry) {
        entry.online = Boolean(contactInfo.online);
        entry.unread_count = 0;
      }
      state.selected = contactInfo.pseudo;
      if (contactThread) {
        contactThread.classList.remove('hidden');
        contactThread.setAttribute('data-current-contact', contactInfo.pseudo);
      }
      if (contactEmpty) {
        contactEmpty.classList.add('hidden');
      }
      clearConversation();
      const messages = Array.isArray(payload.messages) ? payload.messages : [];
      messages.forEach(message => {
        const direction = message.from === pseudo ? 'outgoing' : 'incoming';
        appendMessage(message, direction);
      });
      updateConversationHeader(entry || contactInfo);
      renderContactList();
      updateUnreadBadge();
      requestAnimationFrame(() => {
        scrollConversationToBottom();
        if (conversationInput) {
          conversationInput.focus();
        }
      });
      markConversationRead(contactInfo.pseudo);
    } catch (error) {
      console.error('conversation_open', error);
    }
  }

  function updateConversationHeader(contact) {
    if (!conversationContact || !conversationStatus || !contact) {
      return;
    }
    conversationContact.textContent = contact.pseudo;
    const online = Boolean(contact.online);
    conversationStatus.textContent = online ? 'En ligne' : 'Hors ligne';
    conversationStatus.classList.toggle('is-online', online);
  }

  function appendMessage(message, direction) {
    if (!conversationMessages || !message || !message.id) {
      return;
    }
    if (state.renderedMessages.has(message.id)) {
      return;
    }
    state.renderedMessages.add(message.id);
    const wrapper = document.createElement('div');
    wrapper.className = `conversation__message conversation__message--${direction}`;
    const content = document.createElement('p');
    content.textContent = message.content || '';
    const time = document.createElement('time');
    if (message.created_at) {
      time.dateTime = message.created_at;
    }
    time.textContent = formatTimestamp(message.created_at);
    wrapper.append(content, time);
    conversationMessages.appendChild(wrapper);
    scrollConversationToBottom();
  }

  function scrollConversationToBottom() {
    if (!conversationMessages) {
      return;
    }
    conversationMessages.scrollTop = conversationMessages.scrollHeight;
  }

  function formatTimestamp(value) {
    if (!value) {
      return '';
    }
    const date = new Date(value.replace(' ', 'T'));
    if (Number.isNaN(date.getTime())) {
      return '';
    }
    return date.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
  }

  async function handleConversationSubmit(event) {
    event.preventDefault();
    if (!state.selected || !conversationInput) {
      return;
    }
    const text = conversationInput.value.trim();
    if (!text) {
      return;
    }
    try {
      if (conversationSubmit) {
        conversationSubmit.disabled = true;
      }
      conversationInput.disabled = true;
      const response = await fetch('/contacts/message', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({ to: state.selected, content: text }),
      });
      if (!response.ok) {
        throw new Error('message_send_failed');
      }
      const payload = await response.json();
      if (payload && payload.message) {
        const direction = payload.message.from === pseudo ? 'outgoing' : 'incoming';
        appendMessage(payload.message, direction);
        setContactUnread(state.selected, 0);
        if (conversationInput) {
          conversationInput.value = '';
        }
      }
    } catch (error) {
      console.error('conversation_send', error);
    } finally {
      if (conversationSubmit) {
        conversationSubmit.disabled = false;
      }
      if (conversationInput) {
        conversationInput.disabled = false;
        conversationInput.focus();
      }
    }
  }

  async function markConversationRead(target) {
    if (!target || pendingRead.has(target)) {
      return;
    }
    pendingRead.add(target);
    try {
      await fetch(`/contacts/conversation/${encodeURIComponent(target)}/read`, {
        method: 'POST',
        headers: { Accept: 'application/json' },
      });
    } catch (error) {
      console.error('conversation_mark_read', error);
    } finally {
      pendingRead.delete(target);
    }
  }
})();
