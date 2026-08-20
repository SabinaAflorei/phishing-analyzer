#!/usr/bin/env bash
# Verificare rapida a calitatii limbii romane. Daca output-ul e stalcit,
# incearca: mistral-nemo:12b, qwen2.5:14b-instruct, gemma2:9b.
set -euo pipefail
ollama run "llama3.1:8b" 'Scrie in limba romana corecta, cu diacritice, un raspuns de 3 propozitii catre un coleg care a raportat un email de phishing. Multumeste-i, confirma ca mailul este periculos, cere-i sa il stearga si intreaba daca a dat click sau a introdus date.'
