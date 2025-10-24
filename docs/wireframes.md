# Wireframes & Flows — Neo Arcade Hub

## Hub principal
```
┌───────────────────────────────────────────────────────────────┐
│  LOGO  │ Puissance 4 │ Pendu │ Tetris │ Échecs │ Profil │ Sfx │
│───────────────────────────────────────────────────────────────│
│                                                               │
│    ┌────────────┐   ┌────────────┐   ┌────────────┐           │
│    │ NEON GRID  │   │PAPIER&PIX  │   │DIGITAL BLK │   ...     │
│    │ 3D grille  │   │ texture    │   │ blocs 3D   │           │
│    │ CTA jouer  │   │ CTA jouer  │   │ CTA jouer  │           │
│    └────────────┘   └────────────┘   └────────────┘           │
│                                                               │
│    [Nouvelle partie]    [Classements]    [Paramètres audio]   │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```
- Fond : vortex cyan/magenta animé.
- Cartes : visuels miniatures 4:3 avec gradient par jeu.
- Bouton "Nouvelle partie" centré sous les cartes.

## Puissance 4 — "Neon Grid"
```
┌─────────────────────────────────────────────┐
│ Barre info : Joueur • Score • Bouton retour │
├─────────────────────────────────────────────┤
│  Plateau 3D avec perspective et lueur       │
│  ┌───────────────────────────────────────┐ │
│  │                                       │ │
│  │         (grille 7x6 immersive)        │ │
│  │                                       │ │
│  └───────────────────────────────────────┘ │
│                                             │
│  Message statut (victoire/défaite)          │
│  [Nouvelle partie]        [Changer d'adversaire] │
└─────────────────────────────────────────────┘
```
- Sidebar optionnelle gauche avec historique des coups (`timeline` lumineuse).

## Pendu — "Papier & Pixel"
```
┌─────────────────────────────────────────────┐
│ Barre info papier (motif pointillé)         │
├─────────────────────────────────────────────┤
│ ┌───────────────┐   ┌─────────────────────┐ │
│ │ Hangman SVG   │   │ Mot mystère          │ │
│ │ (dessin neon) │   │ _ _ _ _ _            │ │
│ └───────────────┘   │ Animation texte      │ │
│                     └─────────────────────┘ │
│ [Input lettre] [Valider]                    │
│ Lettres tentées (puces luminescentes)       │
│ Message statut + [Nouvelle partie]          │
└─────────────────────────────────────────────┘
```

## Tetris — "Digital Blocks"
```
┌───────────────────────────────────────────────────────────┐
│ Barre info : Mode Solo/Duel • Scores • Retour • Audio      │
├───────────────────────────────────────────────────────────┤
│  Board principal (centré)    │  Next pieces  │  Hold block │
│  ┌────────────────────────┐  │ ┌───────────┐ │ ┌────────┐ │
│  │                        │  │ │  Prévi 1 │ │ │  Hold │ │
│  │                        │  │ │  Prévi 2 │ │ │       │ │
│  │                        │  │ └───────────┘ │ └────────┘ │
│  └────────────────────────┘  │ Stats & contrôles           │
│                             │ [Nouvelle partie] [Inviter]  │
└───────────────────────────────────────────────────────────┘
```
- Particules en arrière-plan, colonnes latérales en verre fumé.

## Échecs — "Royal Minimal"
```
┌────────────────────────────────────────────────────┐
│ Barre supérieure : Timer • Joueurs • Retour         │
├────────────────────────────────────────────────────┤
│ ┌─────────────────────┐  ┌────────────────────────┐ │
│ │ Damier 3D minimal   │  │ Panneau mouvements     │ │
│ │  (pièces dorées)    │  │ Historique & actions   │ │
│ │                     │  │ [Nouvelle partie]      │ │
│ └─────────────────────┘  │ [Annuler] [Proposer nulle] │
│                          └────────────────────────┘ │
│ Message statut aligné centre bas                     │
└────────────────────────────────────────────────────┘
```
- Damier sur podium réfléchissant, halo or.

## Responsivité
- Mobile : navigation compressée en icônes, carrousel horizontal pour cartes du hub.  
- Orientation paysage tablettes : grille 2 colonnes.  
- Bouton "Nouvelle partie" et messages de statut centrés bas, largeur 100%.

## Flux utilisateur
1. Hub -> sélection jeu via icône (hover 3D) -> transition portail coloré.  
2. Dans chaque jeu, `Nouvelle partie` toujours sous la zone principale de jeu.  
3. Retour hub via icône top-left, même animation.

