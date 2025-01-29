# sk2-irc-python
Prosty klient i serwer IRC napisany w języku Python.

Do działania serwera potrzebny jest pakiet netifaces
```
pip install netifaces
```
Uruchomienie klienta:
```
python ./client.py
```

Uruchomienie serwera:
```
python ./server.py [--ip IP] [--port PORT]
```
Domyślnie serwer startuje używając IP 0.0.0.0 (używa adresu interfejsu sieciowego) i portu 6667.

Zarówno serwer jak i klient używa protokołu TCP do połączenia.

Funkcje serwera:
1. Obsługa połączeń klientów
- Wielowątkowa obsługa klientów
- Zarządzanie połączeniami i ich bezpieczne zamykanie

2. Zarządzanie użytkownikami
- Rejestracja użytkowników (komendy NICK i USER)
- Zmiana nicków
- Weryfikacja dostępności nicków
- Informacje o użytkownikach (komenda USERHOST)

3. System kanałów
- Tworzenie, dołączanie i opuszczanie kanałow (JOIN, PART)
- Tematy kanałów (TOPIC)
- Lista kanałów (LIST)
- Lista użytkowników na kanale (NAMES)

4. Komunikacja
- Wiadomości prywatne między użytkownikami i do kanału (PRIVMSG)
- Powiadomienia o zmianach (dołączenie/opuszczenie kanału, zmiana nicku)
- Obsługa komendy PING/PONG

5. System uprawnień
- Operatorzy kanałów
- Zarządzanie uprawnieniami (MODE)

6. Obsługiwane tryby kanałów (MODE):
- +o: nadanie statusu operatora
- -o: odebranie statusu operatora

7. Obsługa błędów
- Szczegółowe komunikaty błędów
- Zabezpieczenia przed nieprawidłowymi komendami
- Obsługa nieoczekiwanych rozłączeń
- System kodów odpowiedzi zgodny ze standardem IRC

8. Dodatkowe funkcje
- Automatyczne czyszczenie pustych kanałów
- Wsparcie dla Client Capability Negotiation (CAP)
- Formatowanie wiadomości zgodne ze standardem IRC

Funkcje klient:
1. Logowanie
- Użytkownik jest najpierw proszony o podanie Nick, Name, Ip i port serwera

2. Interface
- Klient posiada prosty interface graficzny, po dołączeniu na serwer okno formularza logowania zamyka się i pojawia okno z obsługą serwera
- Dla uproszczenia zostały doddany przyciski do dołączenia na kanał, opuszczenia kanału oraz wysłanie wiadomości (można też enterem)

3. Obsługiwane Komendy:
- ./help (pokazuje wszystkie dostępne komendy)
- JOIN (w okno czatu należy wpisać nazwe kanału np.: #test i nacisną przycisk JOIN)
- PART (przycisk aktywuje się przy dołączeniu na kanał)
- LIST (./list pokazuje dostępne kanały na serwerze, liczbe użytkowników na tych kanałach oraz ustawiony temat)
- NAMES (./names pokazuje liste dostępnych użytkowników na kanale na którym dołączyłeś)
- PRIVMSG (./priv nick wiadomość, wiadomości prywatne)

4. Komunikaty
- Klient odbiera komunikaty od serwera i je formatuje do czytelnej formy (+usuwa nadmierne komunikaty).
- Obsługiwane są komunikaty o dołączeniu na kanał
- Opuszczenie go (czy to przez PART czy Disconnect)
- Wysyłanie wiadomości na kanał bądź prywatnie
