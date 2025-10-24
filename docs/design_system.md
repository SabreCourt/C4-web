# Design System — Neo Arcade Hub

## Vision & Direction
Le site multi-jeux se transforme en un hub futuriste et immersif rappelant une salle d'arcade virtuelle. Chaque univers de jeu conserve une identité forte tout en partageant une base visuelle cohérente, basée sur un glassmorphism léger, des néons subtils et des transitions fluides en 3D.

## Identité globale
- **Palette primaire**  
  - Nuit profonde `#0f172a` (fond principal)  
  - Cyan néon `#38bdf8` (actions et accents lumineux)  
  - Magenta spectral `#f472b6` (éléments secondaires & feedback positif)  
  - Orange solaire `#fb923c` (feedback critique & CTA secondaires)  
  - Texte `#f8fafc` (titres & corps)
- **Dégradés signatures**  
  - **Aurora Cyan** : `linear-gradient(135deg, #38bdf8 0%, #0ea5e9 100%)`  
  - **Pulse Magenta** : `linear-gradient(135deg, #f472b6 0%, #fb7185 100%)`  
  - **Solar Ember** : `linear-gradient(135deg, #fb923c 0%, #f97316 100%)`
- **Typographies**  
  - Titres : [Orbitron](https://fonts.google.com/specimen/Orbitron) (gras 600, tracking +4%)  
  - Corps & UI : [Poppins](https://fonts.google.com/specimen/Poppins) (500 pour labels, 400 pour texte courant)  
  - Alternative système : `font-family: "Orbitron", "Poppins", "Segoe UI", sans-serif;`
- **Icônes**  
  - Style linéaire semi-arrondi, halo lumineux `rgba(56, 189, 248, 0.4)`  
  - Pictogrammes personnalisés pour chaque jeu (voir section "Navigation").

## Tokens & variables CSS
```css
:root {
  /* Couleurs */
  --color-bg: #0f172a;
  --color-surface: rgba(15, 23, 42, 0.65);
  --color-surface-strong: rgba(15, 23, 42, 0.85);
  --color-border: rgba(148, 163, 184, 0.28);
  --color-text: #f8fafc;
  --color-muted: rgba(148, 163, 184, 0.72);
  --color-cyan: #38bdf8;
  --color-magenta: #f472b6;
  --color-orange: #fb923c;

  /* Effets */
  --blur-main: 18px;
  --radius-lg: 28px;
  --radius-md: 18px;
  --radius-sm: 12px;
  --shadow-soft: 0 24px 60px rgba(8, 47, 73, 0.45);
  --shadow-glow: 0 0 22px rgba(56, 189, 248, 0.45);
  --backdrop: blur(var(--blur-main));

  /* Typo */
  --font-display: "Orbitron", "Poppins", "Segoe UI", sans-serif;
  --font-body: "Poppins", "Segoe UI", sans-serif;

  /* Transitions */
  --transition-fast: 180ms ease;
  --transition-base: 320ms cubic-bezier(0.33, 1, 0.68, 1);
  --transition-slow: 640ms cubic-bezier(0.25, 0.1, 0.25, 1);
}
```

## Grilles & espacements
- **Hub & jeux** : grille responsive à 12 colonnes, gutter 24px desktop / 16px mobile.  
- **Cartes de jeu** : ratio 4:3, hauteur min 260px, `padding` interne 24px.  
- **Espacements** : échelle 8px (8, 16, 24, 32, 48).  
- **Alignement** : utilisation d'un conteneur central 1280px max avec marges latérales fluides (`clamp(24px, 8vw, 80px)`).

## Composants principaux
### Navigation hub central
- Barre supérieure flottante en verre, `backdrop-filter` et halo cyan.  
- Icônes :
  - **Puissance 4** : grille 7x6 stylisée, cyan & magenta.  
  - **Pendu** : feuille pliée + curseur néon.  
  - **Tetris** : tétrimino lumineux.  
  - **Échecs** : roi minimaliste en or doux.  
- Interaction : hover => translation `-2px` + halo `box-shadow: var(--shadow-glow)` avec teinte propre au jeu.  
- Active => fond `rgba(56, 189, 248, 0.18)` + trait inférieur dégradé.

### Boutons
- **Primaire** : fond Aurora Cyan, texte `#0f172a`, glow externe `0 12px 24px rgba(56, 189, 248, 0.35)`.  
- **Secondaire** : contour `rgba(56, 189, 248, 0.45)` + fond `rgba(56, 189, 248, 0.08)`.  
- **Danger** : gradient Solar Ember, glow orange faible.  
- Rayon `var(--radius-sm)`, `font-weight: 600`, `letter-spacing: 0.04em`.  
- Animation : micro-parallaxe `transform: translateY(-2px)` et effet `filter: brightness(1.1)` au survol.

### Cartes & panneaux
- Surfaces en verre (`background: var(--color-surface)`) avec `backdrop-filter`.  
- Traits intérieurs `inset 0 0 0 1px rgba(255, 255, 255, 0.06)`.  
- Entêtes en Orbitron 0.85rem uppercase, `letter-spacing: 0.12em`.  
- Accent par jeu via un gradient latéral (2px) rappelant son identité.

### Formulaires
- Champs semi-transparents, `border` cyan 0.5px.  
- Focus : halo interne `0 0 0 2px rgba(56, 189, 248, 0.35)`.  
- Feedback positif : magenta, critique : orange.

### Pop-ups & toasts
- Modal en verre avec `backdrop-filter` renforcé et bordure gradient.  
- Messages victoire/défaite : mêmes couleurs sur tous les jeux (victoire = magenta + cyan, défaite = orange + cyan sombre) avec icône Orbitron stylisé.

## Ambiances par jeu
### Puissance 4 — "Neon Grid"
- **Fond** : grille 3D animée (`linear-gradient` + pseudo-élément) glissant lentement.  
- **Pions** : disques lumineux cyan/magenta avec `box-shadow` vibrant.  
- **Plateau** : perspective légère (rotateX 12°), néons sur les bords.  
- **Son** : bip synthwave discret lors du placement.

### Pendu — "Papier & Pixel"
- **Fond** : texture papier bleu nuit avec motif quadrillé subtil.  
- **Texte** : animations dactylographiées (utiliser `steps()` en CSS).  
- **Interface** : cartes rappelant des fiches perforées, curseur néon cyan.  
- **Son** : clic mécanique doux à chaque lettre.

### Tetris — "Digital Blocks"
- **Fond** : nuage de particules en profondeur, blocs flottants floutés.  
- **Board** : gradient vertical du cyan au magenta, grille lumineuse.  
- **UI** : panneaux en verre noir teinté avec accents magenta.  
- **Son** : pulsations synthé basse fréquence.

### Échecs — "Royal Minimal"
- **Fond** : damier flouté avec reflets or.  
- **Pièces** : silhouettes minimalistes dorées et cyan.  
- **UI** : panneaux minimalistes, typographie en uppercase, grandes marges négatives pour respirer.  
- **Son** : cloche douce lors des coups.

## Animations & transitions globales
- **Entrée page** : `transform: translateZ(-20px) scale(0.96)` -> `scale(1)` avec `opacity` en 420ms (cubic bezier).  
- **Transition hub -> jeu** :
  1. Fondu du hub vers la couleur dominante du jeu (cyan/magenta/orange/or).  
  2. Expansion d'un portail circulaire (scale + blur).  
  3. Zoom-out 3D + flou progressif, puis zoom-in sur la scène du jeu.  
- **Retour au hub** : effet "portail" inversé avec l'icône du jeu comme masque.
- **Hover interactifs** : micro-mouvements `translateZ(6px)` via `transform-style: preserve-3d`.

## Sound design (facultatif)
- Boutons => clics doux `0.08s`, pitch variable.  
- Notifications => tintement magenta (victoire) ou percussion feutrée orange (défaite).  
- Hub => loop ambient de synthé discret -36dB.

## Accessibilité
- Contraste AA assuré (cyan et magenta sur fond nuit).  
- Modes daltoniens : alternative `outline` blanche pour l'état actif.  
- Focus visible (`outline` cyan) + transitions respectant `prefers-reduced-motion`.

## Assets à produire
- Sprite icônes vectorielles pour le menu.  
- Motifs de fond (grille neon, papier texturé, particules, damier).  
- Fichiers audio courtes boucles (ogg/mp3) à intégrer optionnellement.

