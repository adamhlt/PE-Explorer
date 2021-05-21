# PE Explorer [![C++](https://img.shields.io/badge/language-C%2B%2B-%23f34b7d.svg?style=plastic)](https://en.wikipedia.org/wiki/C%2B%2B) [![Windows](https://img.shields.io/badge/platform-Windows-0078d7.svg)](https://en.wikipedia.org/wiki/Microsoft_Windows) [![x86](https://img.shields.io/badge/arch-x86-red.svg)](https://en.wikipedia.org/wiki/X86) 
### Présentation 
Ceci est un exploreur de fichier PE écrit en C++ . Ce projet permet de se familiariser avec la structure des fichiers PE, l'exploreur est compatible avec les deux architectures (x86 / x64).

Les commentaires dans les sources n'expliquent pas en détail la structure des fichiers PE. 

### Utilisation
Cet exploreur s'utilise en ligne de commande de façon très simple.
    explorer.exe <PE File>
Vous pouvez tester l'exploreur avec les fichiers fournis dans le dossier "Release", les deux architectures (x86 et x64) sont présentes pour les fichiers de test.
    explorer.exe test.exe
La commande ci-dessus vous permet de tester l'exploreur avec les fichiers fournis.
### Démonstration
![Démontration de l'injecteur de DLL.](https://github.com/adamhlt/PE-Explorer/blob/main/Ressource/demo.gif)
