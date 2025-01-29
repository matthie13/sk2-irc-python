import socket
from datetime import datetime
import threading
import tkinter as tk
from tkinter import scrolledtext

class IRCClientGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("IRC Client")
        self.master.geometry("900x500")

        # Formularz na dane połączenia
        self.connection_frame = tk.Frame(self.master)
        self.connection_frame.pack(fill=tk.BOTH, padx=10, pady=10)

        self.nickname_label = tk.Label(self.connection_frame, text="Nickname:")
        self.nickname_label.pack(fill=tk.X, pady=(0, 5))
        self.nickname_entry = tk.Entry(self.connection_frame)
        self.nickname_entry.pack(fill=tk.X, pady=(0, 10))

        self.username_label = tk.Label(self.connection_frame, text="Username:")
        self.username_label.pack(fill=tk.X, pady=(0, 5))
        self.username_entry = tk.Entry(self.connection_frame)
        self.username_entry.pack(fill=tk.X, pady=(0, 10))

        self.host_label = tk.Label(self.connection_frame, text="Server Address:")
        self.host_label.pack(fill=tk.X, pady=(0, 5))
        self.host_entry = tk.Entry(self.connection_frame)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.pack(fill=tk.X, pady=(0, 10))

        self.port_label = tk.Label(self.connection_frame, text="Port:")
        self.port_label.pack(fill=tk.X, pady=(0, 5))
        self.port_entry = tk.Entry(self.connection_frame)
        self.port_entry.insert(0, "6667")
        self.port_entry.pack(fill=tk.X, pady=(0, 10))

        self.connect_button = tk.Button(self.connection_frame, text="Connect", command=self.connect)
        self.connect_button.pack(fill=tk.X, pady=(10, 0))

        # Elementy GUI (czat)
        self.chat_frame = tk.Frame(self.master)
        
        # ScrolledText widget for chat log
        self.chat_log = scrolledtext.ScrolledText(self.chat_frame, state='disabled', wrap='word', height=20)
        self.chat_log.pack(fill=tk.BOTH, padx=10, pady=(10, 5), expand=True)

        # Entry for sending messages
        self.message_entry = tk.Entry(self.chat_frame)
        self.message_entry.pack(fill=tk.X, padx=10, pady=(5, 5))
        self.message_entry.bind("<Return>", lambda event: self.send_message())

        # Buttons for additional actions
        button_frame = tk.Frame(self.chat_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.join_button = tk.Button(button_frame, text="Join Channel", command=self.join_channel, state='disabled')
        self.join_button.pack(side=tk.LEFT, padx=5)

        self.send_button = tk.Button(button_frame, text="Send", command=self.send_message, state='disabled')
        self.send_button.pack(side=tk.LEFT, padx=5)

        self.leave_button = tk.Button(button_frame, text="Leave Channel", command=self.part_channel, state='disabled')
        self.leave_button.pack(side=tk.LEFT, padx=5)

        # Dane klienta IRC
        self.server_socket = None
        self.running = False
        self.nickname = "Guest"
        self.username = "Guest"
        self.current_channel = None
        self.channels = {}  # Lista kanałów, do których użytkownik dołączył

    def connect(self):
        """Połączenie z serwerem IRC."""
        self.nickname = self.nickname_entry.get().strip() or "Guest"
        self.username = self.username_entry.get().strip() or "Guest"
        host = self.host_entry.get().strip()
        port = int(self.port_entry.get().strip())

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.connect((host, port))
            self.running = True
            self.log_message(f"Connected to {host}:{port}")

            # Rejestracja użytkownika
            self.send_message_raw(f"NICK {self.nickname}")
            self.send_message_raw(f"USER {self.username} 0 * :{self.username}")

            # Uruchomienie wątku odbierającego wiadomości
            threading.Thread(target=self.receive_messages, daemon=True).start()

            # Ukrywanie formularza i wyświetlanie czatu
            self.connection_frame.pack_forget()
            self.chat_frame.pack(fill=tk.BOTH, padx=10, pady=10)

            # Aktywacja przycisków
            self.join_button.config(state='normal')
            self.send_button.config(state='normal')

        except Exception as e:
            self.log_message(f"Error connecting to server: {e}")

    def join_channel(self):
        """Dołączenie do kanału."""
        channel = self.message_entry.get().strip()
        if channel:
            self.send_message_raw(f"JOIN {channel}")
            self.channels[channel] = []
            self.current_channel = channel
            self.log_message(f"Joined channel [{channel}]")
            # Aktywacja przycisku Leave Channel
            self.message_entry.delete(0, tk.END)
            self.leave_button.config(state='normal')

    def part_channel(self, channel=None):
        """Opuszczenie kanału."""
        if not channel:
            channel = self.current_channel
        if channel:
            self.send_message_raw(f"PART {channel}")
            if channel in self.channels:
                del self.channels[channel]
            if self.current_channel == channel:
                self.current_channel = None
            self.log_message(f"Left channel {channel}")
            # Dezaktywacja przycisku Leave Channel po opuszczeniu kanału
            self.leave_button.config(state='disabled')

    def send_message(self):
        """Wysyłanie wiadomości na bieżący kanał lub prywatną wiadomość."""
        message = self.message_entry.get().strip()

        if message:
            if message.startswith("./list"):
                # Wyślij komendę LIST do serwera
                self.send_message_raw("LIST")
                self.log_message("Requested channel list from server.")
            elif message.startswith("./names"):
            # Wyślij komendę NAMES dla aktualnego kanału
                if self.current_channel:
                    self.send_message_raw(f"NAMES {self.current_channel}")
                    #self.log_message(f"Requested user list for channel {self.current_channel}")
                else:
                    self.log_message("[Error]: You must join a channel first to list users.")
            elif message.startswith("./help"):
                # Wyświetlenie dostępnych komend
                self.show_help()
            elif message.startswith("./priv "):
                # Obsługa prywatnych wiadomości
                parts = message.split(" ", 2)
                if len(parts) > 2:
                    target_nick = parts[1].strip()
                    private_message = parts[2].strip()
                    if private_message:
                        self.send_message_raw(f"PRIVMSG {target_nick} :{private_message}")
                        self.log_message(f"Private message to {target_nick}: {private_message}")
                    else:
                        self.log_message("[Error]: Message content cannot be empty.")
                else:
                    self.log_message("[Error]: No message provided after ./priv <nick> <message>.")
            elif self.current_channel:
                # Wiadomość na kanał
                self.send_message_raw(f"PRIVMSG {self.current_channel} :{message}")
                self.log_message(f"Message to [{self.current_channel}]: {message}")
            else:
                # Wiadomość prywatna, jeśli nie ma kanału
                self.send_message_raw(f"PRIVMSG {self.nickname} :{message}")
                self.log_message(f"Private message to {self.nickname}: {message}")

            # Wyczyść pole wiadomości
            self.message_entry.delete(0, tk.END)

    def send_message_raw(self, message):
        """Wysyłanie wiadomości bezpośrednio do serwera."""
        if self.server_socket:
            self.server_socket.send(f"{message}\r\n".encode('utf-8'))

    def show_help(self):
        """Wyświetlanie dostępnych komend."""
        help_text = (
            "Available commands:\n"
            "./list        - List all available channels\n"
            "./names       - List users on the current channel\n"
            "./help        - Show this help message\n"
            "./priv <nick> <message> - Send a private message to a user\n"
        )
        self.log_message(help_text, is_system=True)

    def receive_messages(self):
        """Odbieranie wiadomości z serwera IRC."""
        while self.running:
            try:
                response = self.server_socket.recv(2048).decode('utf-8')
                if not response:
                    break

                # Logowanie otrzymanych danych
                #self.log_message(f"Received raw data: {response}", is_system=True)

                for line in response.split("\r\n"):
                    if line:
                        self.handle_message(line)
            except Exception as e:
                self.log_message(f"Error receiving messages: {e}")
                break

    def handle_message(self, message):
        """Obsługuje komunikaty serwera."""
        if message.startswith("PING"):
            # Odpowiadamy na PING
            server = message.split(":")[1].strip() if len(message.split(":")) > 1 else ""
            if server:
                self.send_message_raw(f"PONG :{server}")

        elif "PRIVMSG" in message:
            # Obsługuje wiadomości prywatne lub z kanałów
            parts = message.split(" :", 1)
            if len(parts) > 1:
                sender = message.split('!')[0][1:]  # Wyciągamy nadawcę
                message_content = parts[1]  # Treść wiadomości
                channel = message.split(' ')[2] if len(message.split(' ')) > 2 else ""

                if channel.startswith('#'):
                    # Wiadomość na kanał
                    self.log_message(f"[{channel}] {sender}: {message_content}")
                else:
                    # Wiadomość prywatna
                    self.log_message(f"[PRIV] {sender}: {message_content}")

        elif "JOIN" in message:
            # Obsługuje dołączenie do kanału
            parts = message.split(" ")
            if len(parts) >= 3:
                user_info = parts[0]
                user_name = user_info.split('!')[0][1:]  # Wydobycie samego nicku
                channel = parts[2]  # Kanał, do którego dołączono (np. #test)

                if user_name == self.nickname:
                    # Jeśli to Ty dołączasz do kanału
                    if channel not in self.channels:
                        self.channels[channel] = []
                        self.current_channel = channel
                else:
                    # Jeśli inny użytkownik dołącza do kanału
                    self.log_message(f"{user_name} joined channel [{channel}]")

        elif "PART" in message:
            # Obsługuje opuszczenie kanału
            parts = message.split(" ")
            if len(parts) >= 3:
                user_info = parts[0]
                user_name = user_info.split('!')[0][1:]  # Wydobycie samego nicku
                channel = parts[2]  # Kanał, który użytkownik opuszcza (np. #test)

                if user_name == self.nickname:
                    # Jeśli to Ty opuszczasz kanał
                    if channel in self.channels:
                        del self.channels[channel]
                    self.current_channel = None
                else:
                    # Jeśli inny użytkownik opuszcza kanał
                    self.log_message(f"{user_name} left channel [{channel}]")

        elif "001" in message:
            # Powitanie serwera (001)
            welcome_message = message.split(":", 2)[2]
            self.log_message(f"Welcome to the server, {self.nickname}!", is_system=True)

        elif "002" in message:
            # Informacje o hoście (002)
            host_message = message.split(":", 2)[2]
            self.log_message(f"[INFO] {host_message}", is_system=True)

        elif any(code in message for code in ["251", "255", "266"]):
            # Statystyki serwera (251, 255, 266)
            stats_message = message.split(":", 2)[2]
            self.log_message(f"[STATS] {stats_message}", is_system=True)

        elif "375" in message:
            # Początek MOTD (375)
            self.log_message(f"[MOTD] Message of the Day:", is_system=True)

        elif "372" in message:
            # Treść MOTD (372)
            motd_message = message.split(":", 2)[2]
            self.log_message(f"[MOTD] {motd_message}", is_system=True)

        elif "376" in message:
            # Koniec MOTD (376)
            self.log_message(f"[MOTD] End of Message of the Day.", is_system=True)

        elif "322" in message:
            # Odpowiedź z informacjami o kanale (numer 322)
            parts = message.split(" ", 5)
            if len(parts) >= 5:
                channel_name = parts[3]
                user_count = parts[4].split(":")[0]  # Liczba użytkowników
                topic = parts[4].split(":")[1] if ":" in parts[4] else "(No topic)"
                self.log_message(f"[Channel]: {channel_name}, Users: {user_count}, Topic: {topic}")

        elif "353" in message:
            # Odpowiedź na komendę NAMES
            parts = message.split(" ", 5)
            if len(parts) > 4:
                channel_name = parts[4].strip(":")
                users = parts[5].split()
                self.log_message(f"[USERS] {channel_name}: " + ", ".join(users))

        elif "323" in message:
            # Obsługuje odpowiedź o braku kanałów (323)
            if "No channels" in message:
                self.log_message("[INFO] No channels found.", is_system=True)
            else:
                self.log_message(f"End of channel list.", is_system=True)


        elif "QUIT" in message:
            self.handle_quit(message)

    # Usuń komunikaty systemowe (nadmiarowe)
        elif any(code in message for code in ["366", "004", "003", "321"]):
            return

        else:
            # Obsługuje pozostałe komunikaty serwera
            self.log_message(f"[SERVER RAW] {message}", is_system=True)

    def handle_quit(self, message):
        parts = message.split(" :")
        
        if len(parts) >= 2:
            quit_message = parts[1]  # Powód zakończenia połączenia
            user_info = parts[0].split('!')[0][1:]  # Wydobycie nicku
            self.log_message(f"{user_info} has quit the server. Reason: {quit_message}")
        else:
            self.log_message(f"A user has quit the server.")
    
    def log_message(self, message, is_system=False, is_channel_message=False):
        """Logowanie wiadomości w oknie chat log."""
        self.chat_log.config(state='normal')
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        
        # Filtruj komunikaty systemowe, jeśli 'is_system' jest ustawione na False
        if is_system:
            self.chat_log.insert(tk.END, f"{timestamp} [SYSTEM] {message}\n")
        elif is_channel_message:
            self.chat_log.insert(tk.END, f"{timestamp} {message}\n")
        else:
            self.chat_log.insert(tk.END, f"{timestamp} {message}\n")

        self.chat_log.config(state='disabled')
        self.chat_log.see(tk.END)

    def exit_client(self):
        """Zamykanie połączenia i aplikacji."""
        self.running = False
        if self.server_socket:
            self.send_message_raw("QUIT :Goodbye!")
            self.server_socket.close()
        self.master.quit()

# Uruchamianie aplikacji
if __name__ == "__main__":
    root = tk.Tk()
    app = IRCClientGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.exit_client)
    root.mainloop()
