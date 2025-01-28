import argparse
from dataclasses import dataclass, field
from typing import Dict, Set, Optional
import socket
import threading
from typing import Dict, Set
import datetime
import ipaddress
import netifaces ##

@dataclass
class User:
    username: str
    nickname: str
    socket: socket.socket
    connected: bool = True  # Add connection state tracking

    def __hash__(self):
        return hash(self.socket)

    def __eq__(self, other):
        if not isinstance(other, User):
            return False
        return self.socket == other.socket


@dataclass
class Channel:
    name: str
    topic: str = ""
    users: Set[User] = None
    modes: str = ""
    server = None
    channel_ops: Set[User] = field(default_factory=set)
    
    def __post_init__(self) -> None:
        if self.users is None:
            self.users = set()

    def add_user(self, user: User) -> None:
        """
        Dodaj użytkownika do kanału.
        
        Argumenty:
            user (User): Użytkownik do dodania.
        """
        self.users.add(user)

    def remove_user(self, user: User) -> None:
        """
        Usuń użytkownika z kanału. Jeśli jest operatorem, usuwa go również z listy operatorów kanału
        
        Argumenty:
            user (User): Użytkownik do usunięcia.
        """
        self.users.discard(user)
        self.channel_ops.discard(user)

    def add_channel_operator(self, user: User) -> None:
        """
        Dodaj użytkownika jako operatora kanału.
        
        Argumenty:
            user (User): Użytkownik, który ma być operatorem.
        
        Raises:
            ValueError: Jeśli użytkownik nie jest na kanale.
        """
        if user not in self.users:
            raise ValueError(f"{user.nickname} is not in the channel")
        
        self.channel_ops.add(user)

    def remove_channel_operator(self, user: User) -> None:
        """
        Usuń użytkownika z list operatorów kanału.
        
        Argumenty:
            user (User): Użytkownik, który ma być usunięty z listy operatorów.
        """
        self.channel_ops.discard(user)
        
    def is_user_in_channel(self, user: User) -> bool:
        """
        Sprawdź, czy użytkownik znajduje się na kanale.
        
        Argumenty:
            user (User): Użytkownik do sprawdzenia.
        """
        return user in self.users
    
    def is_channel_operator(self, user: User) -> bool:
        """
        Sprawdź, czy użytkownik jest operatorem kanału.
        
        Argumenty:
            user (User): Użytkownik do sprawdzenia.
        
        Zwraca:
            bool: True jeśli użytkownik jest operatorm kanału, False jeśli nie
        """
        return user in self.channel_ops
    
    def broadcast(self, message: str, exclude_user: Optional[User] = None) -> None:
        """
        Wyślij wiadomość do wszystkich użytkowników na kanale, opcjonalnie wykluczając wybranego użytkownika.
        
        Argumenty:
            message (str): Wiadomość do wysłania.
            exclude_user (User, optional): Użytkownik do wykluczenia z odebrania wiadomości. Domyślna wartość to None.
        """
        for user in self.users:
            if user != exclude_user and self.server:
                self.server.send_message(user.socket, message)
    @property
    def user_count(self) -> int:
        """
        Zwraca liczbę użytkowników na kanale.
        
        Zwraca:
            int: Liczba użytkowników na kanale.
        """
        return len(self.users)
    
    @property
    def op_count(self) -> int:
        """
        Zwraca liczbę operatorów kanału.

        Zwraca:
            int: Liczba operatorów kanału.
        """
        return len(self.channel_ops)


class Server:
    def __init__(self, ip: str = "0.0.0.0", port: int = 6667) -> None:
        if ip == "0.0.0.0":
            ip = self.get_network_ip()
            
        try:
            ip_addr = ipaddress.ip_address(ip)
            self.ip = str(ip_addr)
        except ValueError as e:
            raise ValueError(f"ERROR: Invalid IP address: {ip}") from e
        
        if not 1 <= port <= 65535:
            raise ValueError(f"ERROR: Port number must be between 1 and 65535, got {port}")
        
        self.port = port
        self.name = "irc.python.project.com"
        
        # Channel name -> list of users
        self.channels: Dict[str, Channel] = {}
        
        # Socket -> user mapping
        self.clients: Dict[socket.socket, User] = {}
        
        # Track threads
        self.client_threads: Dict[socket.socket, threading.Thread] = {}
        
        # Nickname -> user mapping
        self.nicknames: Dict[str, User] = {}

        self.error_responses = {
            # Błędy dotyczące rejestracji
            "ERR_NEEDMOREPARAMS": f":{self.name} 461 {{nickname}} {{command}} :Not enough parameters",
            "ERR_ALREADYREGISTERED": f":{self.name} 462 {{nickname}} :You may not reregister",
            
            # Błędy dotyczące nickname
            "ERR_NONICKNAMEGIVEN": f":{self.name} 431 * :No nickname given",
            "ERR_ERRONEUSNICKNAME": f":{self.name} 432 * {{nickname}} :Erroneous nickname",
            "ERR_NICKNAMEINUSE": f":{self.name} 433 * {{nickname}} :Nickname is already in use",
            "ERR_NICKCOLLISION": f":{self.name} 436 {{nickname}} :Nickname collision KILL",
            
            # Błędy dotyczące kanału
            "ERR_NOSUCHCHANNEL": f":{self.name} 403 {{nickname}} {{channel}} :No such channel",
            "ERR_NOTONCHANNEL": f":{self.name} 442 {{nickname}} {{channel}} :You're not on that channel",
            "ERR_USERNOTINCHANNEL": f":{self.name} 441 {{nickname}} {{target}} {{channel}} :They aren't on that channel",
            "ERR_CHANNELISFULL": f":{self.name} 471 {{nickname}} {{channel}} :Cannot join channel (+l)",
            "ERR_INVITEONLYCHAN": f":{self.name} 473 {{nickname}} {{channel}} :Cannot join channel (+i)",
            "ERR_BANNEDFROMCHAN": f":{self.name} 474 {{nickname}} {{channel}} :Cannot join channel (+b)",
            
            # Błędy dotyczące użytkownika
            "ERR_NOSUCHNICK": f":{self.name} 401 {{nickname}} {{target}} :No such nick/channel",
            "ERR_USERNOTINCHANNEL": f":{self.name} 441 {{nickname}} {{target}} {{channel}} :They aren't on that channel",
            "ERR_NOTREGISTERED": f":{self.name} 451 * :You have not registered",
            
            # Błędy dotyczące uprawnień
            "ERR_NOPRIVILEGES": f":{self.name} 481 {{nickname}} :Permission Denied- You're not an IRC operator",
            "ERR_CHANOPRIVSNEEDED": f":{self.name} 482 {{nickname}} {{channel}} :You're not channel operator",
        }

    def start(self) -> None:
        self.server_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_fd.bind((self.ip, self.port))
        self.server_fd.listen()
        self.creation_date = datetime.datetime.now()
        print(f"Server started on {self.ip}:{self.port}")

        while True:
            client_fd, address = self.server_fd.accept()
            print(f"New connection from {address}")
            client_td = threading.Thread(
                target=self.handle_client,
                args=(client_fd,),
                daemon=True
            )
            self.client_threads[client_fd] = client_td
            client_td.start()

    def get_network_ip(self) -> str:
        """Get the IP address of the first non-loopback network interface"""
        # Try getting the default route interface first
        try:
            default_gateway = netifaces.gateways()['default']
            if default_gateway and netifaces.AF_INET in default_gateway:
                default_iface = default_gateway[netifaces.AF_INET][1]
                addrs = netifaces.ifaddresses(default_iface)
                if netifaces.AF_INET in addrs:
                    return addrs[netifaces.AF_INET][0]['addr']
        except:
            pass

        # Fallback: check all interfaces
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            # Skip loopback
            if netifaces.AF_INET in addrs and not addrs[netifaces.AF_INET][0]['addr'].startswith('127.'):
                return addrs[netifaces.AF_INET][0]['addr']
                
        # If no suitable interface found, fallback to localhost
        return '127.0.0.1'
    
    def is_nickname_available(self, nickname: str) -> bool:
        return nickname.lower() not in self.nicknames

    def handle_client(self, client_fd: socket.socket) -> None:
        if client_fd._closed:  # Check if socket is already closed
            print("DEBUG: Client socket was closed before handling")
            return

        # Create temporary user object
        self.clients[client_fd] = User("*", "*", client_fd)
        user = self.clients[client_fd]

        try:
            while user.connected:  # Use connected flag instead of True
                if client_fd._closed:  # Double check socket isn't closed
                    print("DEBUG: Socket closed during operation")
                    break

                try:
                    data = client_fd.recv(1024).decode('utf-8')
                    if not data:
                        print(f"DEBUG: Client {user.nickname} disconnected (no data)")
                        break

                    for line in data.split('\n'):
                        if line:
                            print(f"DEBUG: Received command from {user.nickname}: {line}")  # Debug line
                            try:
                                self.handle_command(client_fd, line)
                            except Exception as e:
                                print(f"DEBUG: Error handling command '{line}': {e}")
                                continue  # Continue processing other commands even if one fails


                except (ConnectionResetError, ConnectionAbortedError, socket.error) as e:
                    print(f"ERROR: Connection reset or aborted: {e}")
                    break
                except socket.error as e:
                    print(f"ERROR: Socket error: {e}")
                    break
                except Exception as e:
                    print(f"ERROR: Error receiving data: {e}")
                    break

        except Exception as e:
            print(f"ERROR: Unexpected error in client handler: {e}")

        finally:
            print(f"DEBUG: Client handler ending for {user.nickname}")
            user.connected = False
            if not client_fd._closed:
                try:
                    self.disconnect_user(client_fd)
                    
                except Exception as e:
                    print(f"ERROR: Error during final disconnect: {e}")
                    
                finally:
                    # Always try to disconnect, even if there were errors
                    self.disconnect_user(client_fd)

    def handle_command(self, client_fd: socket.socket, line: str) -> None:
        """
        Metoda przetwarzająca komendy wydawane przez użytkowników.
        
        Argumenty:
            cliend_fd (socket): Socket klienta.
            line (str): String wpisany przez użytkownika.
        """
        try:
            if not line:
                return

            parts = line.split()
            if not parts:
                return

            command = parts[0].upper()
            print(f"DEBUG: Command: {command}, Parts: {parts}")
            
            match parts[0].upper():
                case "PING":
                    self.send_message(client_fd, f"PONG :{parts[1]}" if len(parts) > 1 else "PONG")
                case "NICK":
                    self.handle_nick(client_fd, parts[1])
                case "USER":
                    self.handle_user(client_fd, parts[1:])
                case "JOIN":
                    self.handle_join(client_fd, parts[1])
                case "PRIVMSG":
                    self.handle_privmsg(
                        client_fd, parts[1], ' '.join(parts[2:]))
                case "PART":
                    self.handle_part(client_fd, parts[1], ' '.join(
                        parts[2:]) if len(parts) > 2 else "")
                case "QUIT":
                    self.disconnect_user(client_fd)
                case "CAP":
                    self.handle_cap(client_fd, parts[1:])
                case "USERHOST":
                    self.handle_userhost(client_fd, parts[1:])
                case "LIST":
                    self.handle_list(client_fd)
                case "NAMES":
                    self.handle_names(client_fd, parts[1] if len(parts) > 1 else None)
                case "OP":
                    self.handle_op(client_fd, parts[1], parts[2])
                case "DEOP":
                    self.handle_deop(client_fd, parts[1], parts[2])
                case "MODE":
                    self.handle_mode(client_fd, parts[1:])
                case "TOPIC":
                    self.handle_topic(client_fd, parts[1], ' '.join(parts[2:]) if len(parts) > 2 else "")
                case _:
                    print(f"Unknown command: {parts[0]}")

        except IndexError:
            print(f"Malformed command: {line}")
        except Exception as e:
            print(f"Error handling command {line}: {e}")

    def handle_cap(self, client_fd: socket.socket, args: list) -> None:
        """Handle CAP (Client Capability) command"""
        if not args:
            return

        subcmd = args[0].upper()
        match subcmd:
            case "LS":
                # List supported capabilities (we support none for now)
                self.send_message(client_fd, "CAP * LS :")
            case "END":
                # Client is done negotiating capabilities
                pass

    def handle_userhost(self, client_fd: socket.socket, args: list) -> None:
        """Handle USERHOST command
        Syntax: USERHOST <nickname> [<nickname> <nickname> ...]
        Returns information about the specified nicknames
        """
        if not args:
            self.send_message(
                client_fd, 
                self.error_responses["ERR_NEEDMOREPARAMS"].format(
                    nickname="*", 
                    command="USERHOST"
                )
            )
            return

        user = self.clients[client_fd]
        hostname = "localhost"  # Or get actual hostname
        
        # Process each requested nickname
        replies = []
        for nickname in args[:5]:  # RFC specifies max 5 nicknames per USERHOST command
            target_user = self.nicknames.get(nickname.lower())
            if target_user:
                # Format: nickname=+username@host (+ indicates user is not away)
                replies.append(f"{target_user.nickname}=+{target_user.username}@{hostname}")
        
        # Send single reply with all found users
        if replies:
            self.send_message(
                client_fd, 
                f":{self.name} 302 {user.nickname} :{' '.join(replies)}"
            )
        else:
            # If no nicknames were found, send empty reply
            self.send_message(
                client_fd, 
                f":{self.name} 302 {user.nickname} :"
            )

    def handle_nick(self, client_fd: socket.socket, nickname: str) -> None:       
        user = self.clients[client_fd]
        old_nick = user.nickname

        # Check if nickname is available
        if not self.is_nickname_available(nickname):
            self.send_message(
                client_fd, self.error_responses.get("ERR_NICKNAMEINUSE").format(nickname=nickname))
            return

        # If this is initial registration (temporary nickname)
        if old_nick == "*":
            user.nickname = nickname
            # Store lowercase for case-insensitive lookup
            self.nicknames[nickname.lower()] = user
            return

        # Update nickname mappings
        if old_nick.lower() in self.nicknames:  # Check lowercase version
            del self.nicknames[old_nick.lower()]
        self.nicknames[nickname.lower()] = user  # Store lowercase
        user.nickname = nickname  # But keep original case for display

        # Broadcast nickname change to all channels user is in
        nick_change_msg = f":{old_nick}!{user.username} NICK :{nickname}"
        for channel in self.channels.values():
            if user in channel.users:
                channel.broadcast(nick_change_msg)

    def handle_user(self, client_fd: socket.socket, args: list) -> None:
        """Handle USER command
        Format: USER <username> <hostname> <servername> :<realname>
        """
        print(f"DEBUG: USER args: {args} (length: {len(args)})")  # Debug the incoming args

        if len(args) < 4:
            self.send_message(
                client_fd, 
                self.error_responses["ERR_NEEDMOREPARAMS"].format(
                    nickname="*", 
                    command="USER"
                )
            )
            return
        
        try:
            username, hostname, servername = args[0:3]

            # Ensure realname is properly formatted and safe to join
            realname_parts = args[3:] if len(args) > 3 else []
            print(f"DEBUG: realname parts before join: {realname_parts}")  # Debugging line

            realname = " ".join(realname_parts).lstrip(':') if realname_parts else ""
            
            # Get the client object
            user = self.clients.get(client_fd)
            if not user:
                print("DEBUG: No user found for USER command")
                self.send_message(
                    client_fd, 
                    self.error_responses["ERR_NOTREGISTERED"].format(nickname="*")
                )
                return

            # Set the username
            user.username = username

            # If both nickname and username are set (no longer "*"), complete registration
            if user.nickname != "*" and user.username != "*":
                # Welcome messages
                server_name = self.name
                hostname = self.ip + ":" + str(self.port)
                server_creation_date = self.creation_date
                
                # Format: nickname!username@hostname
                userhost = f"{user.nickname}!{username}@{hostname}"
                
                self.send_message(client_fd, f":{server_name} 001 {user.nickname} :Welcome to {server_name} {userhost}")
                self.send_message(client_fd, f":{server_name} 002 {user.nickname} :Your host is {server_name}, running version 1.0")
                self.send_message(client_fd, f":{server_name} 003 {user.nickname} :This server was created {server_creation_date}")
                self.send_message(client_fd, f":{server_name} 004 {user.nickname} :{server_name} 1.0 wo ntO")

        except Exception as e:
            print(f"ERROR: Error in handle_user: {e}") 

    def handle_join(self, client_fd: socket.socket, channel: str) -> None:
        # Upewnij się, że nazwa kanału zaczyna się od #
        if not channel.startswith('#'):
            channel = '#' + channel

        user = self.clients[client_fd]
        is_first_user = False
        # Utwórz kanał, jeśli taki nie istnieje
        if channel not in self.channels:
            self.create_channel(channel)
            # Pierwszy użytkownik staję sie automatycznie operatorem
            is_first_user = True

        channel_obj = self.channels[channel]

        # Dodaj użytkownika do kanału
        channel_obj.add_user(user)
        if is_first_user:
            channel_obj.add_channel_operator(user)

        # Wyślij potwierdzenie JOIN do użytkownika
        join_message = f":{user.nickname}!{user.username} JOIN {channel}"
        self.send_message(client_fd, join_message)

        # Wyślij powiadomienie o dołączeniu do innych użytkowników
        channel_obj.broadcast(join_message)

        # Wyślij do użytkownika TOPIC kanału
        if channel_obj.topic:
            self.send_message(client_fd, f":server 332 {user.nickname} {channel} :{channel_obj.topic}")
            
        # Wyślij do użytkownika listę obenych użytkowników kanału
        names_list = []
        for u in channel_obj.users:
            # Operatorzy dostają prefix @
            prefix = '@' if channel_obj.is_channel_operator(u) else ''
            names_list.append(f"{prefix}{u.nickname}")
    
        names_str = " ".join(names_list)
        self.send_message(client_fd, f":server 353 {user.nickname} = {channel} :{names_str}")
        self.send_message(client_fd, f":server 366 {user.nickname} {channel} :End of /NAMES list")

    def handle_part(self, client_fd: socket.socket, channel: str, reason: str = "") -> None:
        """Handle PART command to leave a channel"""
        if not channel.startswith('#'):
            channel = '#' + channel

        user = self.clients[client_fd]

        if channel not in self.channels:
            self.send_message(
                client_fd, 
                self.error_responses["ERR_NOSUCHCHANNEL"].format(
                    nickname=user.nickname, 
                    channel=channel
                )
            )
            return

        channel_obj = self.channels[channel]

        if user not in channel_obj.users:
            self.send_message(
                client_fd, 
                self.error_responses["ERR_NOTONCHANNEL"].format(
                    nickname=user.nickname, 
                    channel=channel
                )
            )
            return

        # Format the PART message
        part_message = f":{user.nickname}!{
            user.username}@localhost PART {channel}"
        if reason:
            part_message += f" :{reason}"

        # Broadcast the departure to the channel
        channel_obj.broadcast(part_message, self)

        # Remove user from channel
        channel_obj.remove_user(user)

        # Remove empty channels
        if not channel_obj.users:
            del self.channels[channel]

    def handle_privmsg(self, client_fd: socket.socket, target: str, message: str) -> None:
        sender = self.clients[client_fd]

        # Format the message according to IRC protocol
        formatted_msg = f":{sender.nickname}!{sender.username} PRIVMSG {target} :{message}"

        # If target is a channel
        if target.startswith('#'):
            if target not in self.channels:
                self.send_message(
                    client_fd, 
                    self.error_responses["ERR_NOSUCHCHANNEL"].format(
                        nickname=sender.nickname, 
                        channel=target
                    )
                )
                return

            channel = self.channels[target]
            if sender not in channel.users:
                self.send_message(
                    client_fd, 
                    self.error_responses["ERR_NOTONCHANNEL"].format(
                        nickname=sender.nickname, 
                        channel=target
                    )
                )
                return

            # Broadcast to all users in channel except sender
            for user in channel.users:
                if user != sender:
                    self.send_message(user.socket, formatted_msg)

        # If target is a user (private message)
        else:
            if not self.is_nickname_available(target):  # if nickname exists
                target_user = self.nicknames[target.lower()]
                self.send_message(target_user.socket, formatted_msg)
            else:
                self.send_message(
                    client_fd, 
                    self.error_responses["ERR_NOSUCHNICK"].format(
                        nickname=sender.nickname, 
                        target=target
                    )
                )

    def handle_list(self, client_fd: socket.socket) -> None:
        """Handle LIST command
        
        Sends information about all visible channels to the user
        
        Args:
            client_fd: The socket connection to the client
        """
        user = self.clients[client_fd]
    
        # RPL_LISTSTART (321)
        self.send_message(client_fd, f":{self.name} 321 {user.nickname} Channel :Users Name")
        
        # RPL_LIST (322)
        for channel_name, channel in self.channels.items():
            # Note the space before the colon in topic part
            if channel.topic:
                topic = f" :{channel.topic}"
            else:
                topic = " :No topic set"
                
            self.send_message(
                client_fd,
                f":{self.name} 322 {user.nickname} {channel_name} {channel.user_count}{topic}"
            )
        
        # RPL_LISTEND (323)
        self.send_message(client_fd, f":{self.name} 323 {user.nickname} :End of /LIST")
    
    def handle_names(self, client_fd: socket.socket, channel_name: Optional[str] = None) -> None:
        """
        Metoda obsługująca polecenie /NAMES.
        Wysyła do użytkownika listę użytkowników na wszystkich kanałach, lub na określonym kanale.
        
        Argumenty:
            client_fd (socket): Socket użytkownika.
            channel_name (str, optional): Nazwa kanału, którego listę użytkowników chcemy. Domyślnie None.
        """
        user = self.clients[client_fd]
        if channel_name is not None:
            if not channel_name.startswith('#'):
                channel_name = '#' + channel_name
            
        if channel_name:
            if channel_name not in self.channels:
                self.send_message(
                    client_fd,
                    self.error_responses["ERR_NOSUCHCHANNEL"].format(
                        nickname=user.nickname,
                        channel=channel_name
                    )
                )
                return
                
            channel = self.channels[channel_name]
            names_list = [f"{'@' if channel.is_channel_operator(u) else ''}{u.nickname}" for u in channel.users]
            self.send_message(client_fd, f":{self.name} 353 {user.nickname} = {channel_name} :{' '.join(names_list)}")
            self.send_message(client_fd, f":{self.name} 366 {user.nickname} {channel_name} :End of /NAMES list")
        else:
            for chan_name, channel in self.channels.items():
                names_list = [f"{'@' if channel.is_channel_operator(u) else ''}{u.nickname}" for u in channel.users]
                self.send_message(client_fd, f":{self.name} 353 {user.nickname} = {chan_name} :{' '.join(names_list)}")
            self.send_message(client_fd, f":{self.name} 366 {user.nickname} * :End of /NAMES list")
    
    def handle_op(self, client_fd: socket.socket, channel_name: str, target_nick: str) -> None:
        """
        Metoda obsługująca polecenie /OP. Nadaje uprawnienia operatora wybranemu użytkownikowi na podanym kanale.
        """
        user = self.clients[client_fd]
        
        if not channel_name.startswith('#'):
            channel_name = '#' + channel_name
            
        if channel_name not in self.channels:
            self.send_message(
                client_fd,
                self.error_responses["ERR_NOSUCHCHANNEL"].format(
                    nickname=user.nickname,
                    channel=channel_name
                )
            )
            return
            
        channel = self.channels[channel_name]
        
        # Sprawdź, czy użytkownik jest operatorem (może nadawać innym uprawnienia operatora)
        if not channel.is_channel_operator(user):
            self.send_message(
                client_fd,
                self.error_responses["ERR_CHANOPRIVSNEEDED"].format(
                    nickname=user.nickname,
                    channel=channel_name
                )
            )
            return
            
        # Znajdź użytkownika docelowego
        target_user = self.nicknames.get(target_nick.lower())
        if not target_user:
            self.send_message(
                client_fd,
                self.error_responses["ERR_NOSUCHNICK"].format(
                    nickname=user.nickname,
                    target=target_nick
                )
            )
            return
            
        if target_user not in channel.users:
            self.send_message(
                client_fd,
                self.error_responses["ERR_USERNOTINCHANNEL"].format(
                    nickname=user.nickname,
                    target=target_nick,
                    channel=channel_name
                )
            )
            return
            
        # Dodaj status operatora
        channel.add_channel_operator(target_user)
        channel.broadcast(f":{user.nickname}!{user.username} MODE {channel_name} +o {target_user.nickname}")
    
    def handle_deop(self, client_fd: socket.socket, channel_name: str, target_nick: str) -> None:
        """
        Metoda obsługująca polecenie /DEOP. Zabiera uprawnienia operatora wybranemu użytkownikowi na podanym kanale.
        """
        # Kod podobny jak w handle_op, tylko tym razem używamy remove_channel_operator
        user = self.clients[client_fd]
        
        if not channel_name.startswith('#'):
            channel_name = '#' + channel_name
            
        if channel_name not in self.channels:
            self.send_message(
                client_fd,
                self.error_responses["ERR_NOSUCHCHANNEL"].format(
                    nickname=user.nickname,
                    channel=channel_name
                )
            )
            return
            
        channel = self.channels[channel_name]
        
        if not channel.is_channel_operator(user):
            self.send_message(
                client_fd,
                self.error_responses["ERR_CHANOPRIVSNEEDED"].format(
                    nickname=user.nickname,
                    channel=channel_name
                )
            )
            return
            
        target_user = self.nicknames.get(target_nick.lower())
        if not target_user:
            self.send_message(
                client_fd,
                self.error_responses["ERR_NOSUCHNICK"].format(
                    nickname=user.nickname,
                    target=target_nick
                )
            )
            return
            
        if target_user not in channel.users:
            self.send_message(
                client_fd,
                self.error_responses["ERR_USERNOTINCHANNEL"].format(
                    nickname=user.nickname,
                    target=target_nick,
                    channel=channel_name
                )
            )
            return
            
        channel.remove_channel_operator(target_user)
        channel.broadcast(f":{user.nickname}!{user.username} MODE {channel_name} -o {target_user.nickname}")  
    
    def handle_topic(self, client_fd: socket.socket, channel_name: str, new_topic: str = "") -> None:
        """Handle TOPIC command
        If new_topic is empty, show current topic
        If new_topic is not empty, set new topic (requires channel operator status)
        """
        user = self.clients[client_fd]
        
        if not channel_name.startswith('#'):
            channel_name = '#' + channel_name

        # Check if channel exists
        if channel_name not in self.channels:
            self.send_message(
                client_fd,
                self.error_responses["ERR_NOSUCHCHANNEL"].format(
                    nickname=user.nickname,
                    channel=channel_name
                )
            )
            return

        channel = self.channels[channel_name]

        # Check if user is in channel
        if user not in channel.users:
            self.send_message(
                client_fd,
                self.error_responses["ERR_NOTONCHANNEL"].format(
                    nickname=user.nickname,
                    channel=channel_name
                )
            )
            return

        # If no topic provided, show current topic
        if not new_topic:
            if channel.topic:
                self.send_message(client_fd, f":{self.name} 332 {user.nickname} {channel_name} :{channel.topic}")
            else:
                self.send_message(client_fd, f":{self.name} 331 {user.nickname} {channel_name} :No topic is set")
            return

        # Setting new topic requires channel operator status
        if not channel.is_channel_operator(user):
            self.send_message(
                client_fd,
                self.error_responses["ERR_CHANOPRIVSNEEDED"].format(
                    nickname=user.nickname,
                    channel=channel_name
                )
            )
            return

        # Set new topic and notify channel
        channel.topic = new_topic.lstrip(':')
        channel.broadcast(f":{user.nickname}!{user.username} TOPIC {channel_name} :{channel.topic}")
    
    def handle_mode(self, client_fd: socket.socket, args: list) -> None:
        """
        Handle MODE command
        Format: MODE <channel> <mode> [<args>]
        Currently supported modes:
        +o/-o - Give/take channel operator status
        """
        user = self.clients[client_fd]
        
        if len(args) < 2:
            self.send_message(
                client_fd,
                self.error_responses["ERR_NEEDMOREPARAMS"].format(
                    nickname=user.nickname,
                    command="MODE"
                )
            )
            return

        channel_name = args[0]
        if not channel_name.startswith('#'):
            channel_name = '#' + channel_name
        
        # Check if channel exists
        if channel_name not in self.channels:
            self.send_message(
                client_fd,
                self.error_responses["ERR_NOSUCHCHANNEL"].format(
                    nickname=user.nickname,
                    channel=channel_name
                )
            )
            return

        channel = self.channels[channel_name]
        mode = args[1]

        # Currently only handling operator status changes
        if mode in ['+o', '-o']:
            if len(args) < 3:
                self.send_message(
                    client_fd,
                    self.error_responses["ERR_NEEDMOREPARAMS"].format(
                        nickname=user.nickname,
                        command="MODE"
                    )
                )
                return

            # Check if user is operator
            if not channel.is_channel_operator(user):
                self.send_message(
                    client_fd,
                    self.error_responses["ERR_CHANOPRIVSNEEDED"].format(
                        nickname=user.nickname,
                        channel=channel_name
                    )
                )
                return

            target_nick = args[2]
            target_user = self.nicknames.get(target_nick.lower())
            
            if not target_user:
                self.send_message(
                    client_fd,
                    self.error_responses["ERR_NOSUCHNICK"].format(
                        nickname=user.nickname,
                        target=target_nick
                    )
                )
                return

            if target_user not in channel.users:
                self.send_message(
                    client_fd,
                    self.error_responses["ERR_USERNOTINCHANNEL"].format(
                        nickname=user.nickname,
                        target=target_nick,
                        channel=channel_name
                    )
                )
                return

            if mode == '+o':
                channel.add_channel_operator(target_user)
            else:  # -o
                channel.remove_channel_operator(target_user)

            # Notify channel of mode change
            channel.broadcast(f":{user.nickname}!{user.username} MODE {channel_name} {mode} {target_user.nickname}")
   
    def create_channel(self, name: str, topic: str = "") -> Channel:
        if name in self.channels:
            raise ValueError(f"Channel {name} already exists")
        channel = Channel(name=name, topic=topic)
        channel.server = self  # Set the server reference
        self.channels[name] = channel
        return channel

    def send_message(self, client_fd: socket.socket, message: str) -> None:
        try:
            full_message = f"{message}\r\n"
            print(f"DEBUG: Sending raw bytes: {full_message.encode('utf-8')}")
            client_fd.send(full_message.encode('utf-8'))
        except Exception as e:
            print(f"Error sending message: {e}")

    def disconnect_user(self, client_fd: socket.socket) -> None:
        """
        Disconnect a user and clean up their presence in channels and server lists.

        Args:
            client_fd: The socket connection to the client
        """
        try:
            if client_fd not in self.clients:
                print("DEBUG: Client not found in clients dictionary")
                return

            user = self.clients[client_fd]
            if not user.connected:  # Already disconnected
                print(f"DEBUG: User {user.nickname} already disconnected")
                return

            user.connected = False  # Mark as disconnected first
            print(f"DEBUG: Disconnecting user {user.nickname}")  # Debug line

            # Remove from all channels
            # Create a copy of values to iterate
            for channel in list(self.channels.values()):
                try:
                    if user in channel.users:
                        channel.remove_user(user)
                        # Only broadcast if there are other users and they're still connected
                        if channel.users:
                            channel.broadcast(f":{user.nickname}!{user.username} QUIT :Connection closed", self)
                            print(f"DEBUG: Removed {user.nickname} from channel {channel.name}")  # Debug
                except Exception as e:
                    print(f"ERROR: Error removing user from channel: {e}")

            # Clean up server mappings
            try:
                if user.nickname in self.nicknames:
                    del self.nicknames[user.nickname.lower()]
                del self.clients[client_fd]
                print(f"DEBUG: Cleaned up mappings for {user.nickname}")  # Debug
            except Exception as e:
                print(f"ERROR: Error cleaning up user mappings: {e}")

            # Thread cleanup
            if client_fd in self.client_threads:
                print(f"DEBUG: Removing thread for {user.nickname}")  # Debug
                del self.client_threads[client_fd]

        except Exception as e:
            print(f"ERROR: Error during disconnect cleanup: {e}")

        finally:
            if not client_fd._closed:  # Check if socket is already closed
                try:
                    # Properly shutdown the socket
                    client_fd.shutdown(socket.SHUT_RDWR)
                except socket.error:
                    print(f"ERROR: Error shutting down socket: {e}")
                try:
                    client_fd.close()
                except socket.error:
                    print(f"ERROR: Error closing socket: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description='Python IRC Server')
    parser.add_argument('--ip', type=str, default="0.0.0.0", 
                      help='IP address to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=6667,
                      help='Port to listen on (default: 6667)')
    
    args = parser.parse_args()
    
    try:
        irc_server = Server(args.ip, args.port)
        print(f"Starting IRC server on {args.ip}:{args.port}")
        irc_server.start()
    except ValueError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
