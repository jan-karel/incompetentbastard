# Agentdashboard lokaal testen

Open `tests/agents_history.html` rechtstreeks in een browser, bijvoorbeeld door
het bestand naar het browservenster te slepen. De pagina voert automatisch tien
controles uit en toont `GESLAAGD: 10 controles.` of een foutmelding.

De test gebruikt gewone JavaScript met `'use strict'`, een echte browser-DOM en
fictieve API-antwoorden. Er is geen Node.js, npm, bundler, externe library of
webserver nodig. De test verstuurt geen netwerkverzoeken en voert geen
agentopdrachten uit.

De HTML-pagina laadt de echte dashboardcode uit `static/js/agents.js`.
De controles omvatten status- en resultaatwijzigingen bij hetzelfde aantal
opdrachten, HTML-escaping, ongewijzigde uitvoer, wisselen tussen agents,
vertraagde antwoorden, mislukte verzoeken en een lege geschiedenis.

De dashboardcode zelf draait eveneens rechtstreeks in de browser; Flask blijft
de bestaande backend.
