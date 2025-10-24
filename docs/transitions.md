# Transitions & Animations — Neo Arcade Hub

## Principes généraux
- Animation par défaut : `cubic-bezier(0.33, 1, 0.68, 1)` pour l'entrée/sortie.
- Respecter `prefers-reduced-motion` en désactivant les translations et en gardant uniquement un fondu doux.
- Utiliser `transform-style: preserve-3d` sur les conteneurs pour les effets de profondeur.

## Transition Hub → Jeu
1. **Préparation (0–120ms)** : le hub passe en flou progressif (`filter: blur(10px)`), les cartes se compressent (`scale(0.94)`).  
2. **Portail lumineux (120–420ms)** : un cercle cyan/magenta se dilate depuis l'icône du jeu (`scale` + `box-shadow` pulsé).  
3. **Zoom 3D (420–720ms)** : la caméra simule un recul (`translateZ(-60px)`) puis un zoom vers la scène du jeu (`translateZ(0)`).  
4. **Color wash (synchro)** : un dégradé plein écran prend la teinte du jeu (cf. thèmes).  
5. **Arrivée (720–900ms)** : la scène du jeu apparaît en fondu avec légère translation ascendante.

## Transition Jeu → Hub
- Effet miroir : contraction du plateau (`scale(0.92)`), apparition du portail dans la couleur du jeu, puis fondu vers le hub.
- Le bouton "Retour hub" déclenche un son doux et la disparition des éléments UI en cascade (`staggered delay` 40ms).

## Animations spécifiques
### Navigation hub
- Hover icônes : `translateZ(6px)` + halo spécifique (`box-shadow`) + légère rotation `rotateX(6deg)`.
- Active : barre inférieure dégradée qui glisse (`width` de 0 à 100%).

### Bouton "Nouvelle partie"
- Apparition : `opacity` 0 → 1 sur 280ms, `translateY(12px)` → 0.  
- Hover : lueur cyan pulsée (`box-shadow` animé `@keyframes pulseGlow`).

### Messages victoire / défaite
- Entrée : slide depuis le bas (`translateY(24px)` → 0) + `opacity` 0 → 1.  
- Victoire : gradient magenta/cyan animé (`background-position` anime sur 6s).  
- Défaite : gradient orange/cyan sombre, vibration très légère (`@keyframes shake-soft`).

### Jeux
- **Puissance 4** : grille arrière-plan se déplace lentement (`background-position` 0 → 100% sur 40s). Les pions tombent avec inertie (`cubic-bezier(0.35, 0, 0.2, 1.3)`).
- **Pendu** : effet dactylographie sur le mot (`animation: typing steps(n)`), curseur clignotant magenta. Les lettres incorrectes se froissent (`transform: rotate(-4deg) scale(0.96)` + `filter: grayscale(1)`).
- **Tetris** : blocs en arrière-plan oscillent (`@keyframes floatBlock`) avec `translateY` ±12px. La zone Next effectue un `glow` magenta.
- **Échecs** : plateau apparaît via `scale(0.95) → 1`, pièces glissent avec `transform` 3D et ombre portée or. Historique des coups défile via `mask-image` gradient.

## Effets audio suggérés
- **Hover** : clic futuriste `0.06s` (sine montée).  
- **Validation** : balayage cyan (pitch 440Hz → 660Hz).  
- **Erreur** : son percussif doux (pitch 220Hz).  
- **Victoire** : arpège magenta (triade majeure).  
- **Défaite** : souffle grave court.

