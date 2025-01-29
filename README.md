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
