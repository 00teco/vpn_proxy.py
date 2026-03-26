#!/usr/bin/env python3
"""
GitHub VPN Proxy - Funciona SEM permissão de administrador
Intercepta tráfego de aplicativos específicos como uma VPN de nível de aplicação
Baseado em SOCKS5 proxy + tunelamento automático
"""

import os
import sys
import json
import socket
import select
import struct
import threading
import argparse
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import logging

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vpn_proxy.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class TrafficLog:
    """Registro de tráfego interceptado"""
    timestamp: str
    app_name: str
    src_addr: str
    dst_addr: str
    dst_port: int
    bytes_sent: int
    bytes_received: int
    protocol: str


class SOCKS5Server:
    """
    Servidor SOCKS5 que funciona como VPN de nível de aplicação
    Não requer privilégios administrativos - roda em userspace
    """
    
    def __init__(self, host: str = '127.0.0.1', port: int = 1080, 
                 allowed_apps: Optional[List[str]] = None):
        self.host = host
        self.port = port
        self.allowed_apps = allowed_apps or []  # Apps específicos para interceptar
        self.running = False
        self.socket = None
        self.connections: Dict[socket.socket, dict] = {}
        self.traffic_logs: List[TrafficLog] = []
        self.log_file = f"traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Estatísticas
        self.stats = {
            'total_connections': 0,
            'active_connections': 0,
            'bytes_transferred': 0
        }
        
    def start(self):
        """Inicia o servidor SOCKS5"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(100)
            self.running = True
            
            logger.info(f"🚀 VPN Proxy SOCKS5 iniciado em {self.host}:{self.port}")
            logger.info("⚡ Sem necessidade de permissão de administrador!")
            logger.info("📱 Configure aplicativos específicos para usar este proxy")
            logger.info("🛑 Pressione Ctrl+C para parar\n")
            
            # Aceita conexões
            while self.running:
                try:
                    client, addr = self.socket.accept()
                    self.stats['total_connections'] += 1
                    self.stats['active_connections'] += 1
                    
                    # Thread para cada conexão
                    thread = threading.Thread(
                        target=self._handle_client,
                        args=(client, addr)
                    )
                    thread.daemon = True
                    thread.start()
                    
                except socket.error as e:
                    if self.running:
                        logger.error(f"Erro ao aceitar conexão: {e}")
                        
        except Exception as e:
            logger.error(f"Erro ao iniciar servidor: {e}")
        finally:
            self.stop()
    
    def _handle_client(self, client: socket.socket, addr: Tuple[str, int]):
        """Gerencia conexão de um cliente"""
        try:
            # Handshake SOCKS5
            if not self._socks5_handshake(client):
                return
            
            # Processa request SOCKS5
            remote, dst_addr, dst_port = self._socks5_request(client)
            if not remote:
                return
            
            # Registra conexão
            conn_info = {
                'client': client,
                'remote': remote,
                'addr': addr,
                'dst': (dst_addr, dst_port),
                'start_time': datetime.now(),
                'bytes_sent': 0,
                'bytes_recv': 0
            }
            self.connections[client] = conn_info
            
            logger.info(f"🔗 Conexão estabelecida: {addr[0]} -> {dst_addr}:{dst_port}")
            
            # Tunelamento bidirecional
            self._tunnel(conn_info)
            
        except Exception as e:
            logger.error(f"Erro na conexão {addr}: {e}")
        finally:
            self._close_connection(client)
    
    def _socks5_handshake(self, client: socket.socket) -> bool:
        """Realiza handshake SOCKS5"""
        try:
            # Recebe métodos de autenticação
            data = client.recv(2)
            if len(data) < 2:
                return False
            
            version, nmethods = struct.unpack('!BB', data)
            methods = client.recv(nmethods)
            
            # Aceita sem autenticação (0x00)
            client.sendall(struct.pack('!BB', 0x05, 0x00))
            return True
            
        except Exception as e:
            logger.error(f"Handshake falhou: {e}")
            return False
    
    def _socks5_request(self, client: socket.socket) -> Tuple[Optional[socket.socket], str, int]:
        """Processa request SOCKS5 e conecta ao destino"""
        try:
            # Recebe request
            header = client.recv(4)
            if len(header) < 4:
                return None, "", 0
            
            version, cmd, reserved, atyp = struct.unpack('!BBBB', header)
            
            if cmd != 0x01:  # CONNECT apenas
                client.sendall(struct.pack('!BBBBIH', 0x05, 0x07, 0x00, 0x01, 0, 0))
                return None, "", 0
            
            # Lê endereço de destino
            if atyp == 0x01:  # IPv4
                addr_bytes = client.recv(4)
                dst_addr = socket.inet_ntoa(addr_bytes)
            elif atyp == 0x03:  # Domain name
                length = client.recv(1)[0]
                dst_addr = client.recv(length).decode('utf-8')
            else:
                client.sendall(struct.pack('!BBBBIH', 0x05, 0x08, 0x00, 0x01, 0, 0))
                return None, "", 0
            
            # Porta de destino
            port_bytes = client.recv(2)
            dst_port = struct.unpack('!H', port_bytes)[0]
            
            # Conecta ao destino real
            try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.settimeout(30)
                remote.connect((dst_addr, dst_port))
                
                # Responde sucesso
                bind_addr = remote.getsockname()
                addr_packed = socket.inet_aton(bind_addr[0])
                client.sendall(struct.pack('!BBBB', 0x05, 0x00, 0x00, 0x01) + addr_packed + struct.pack('!H', bind_addr[1]))
                
                return remote, dst_addr, dst_port
                
            except Exception as e:
                logger.error(f"Falha ao conectar em {dst_addr}:{dst_port}: {e}")
                client.sendall(struct.pack('!BBBBIH', 0x05, 0x05, 0x00, 0x01, 0, 0))
                return None, "", 0
                
        except Exception as e:
            logger.error(f"Erro no request SOCKS5: {e}")
            return None, "", 0
    
    def _tunnel(self, conn_info: dict):
        """Tunelamento bidirecional de dados"""
        client = conn_info['client']
        remote = conn_info['remote']
        
        try:
            while self.running:
                # Usa select para multiplexação
                readable, _, _ = select.select([client, remote], [], [], 1)
                
                for sock in readable:
                    data = sock.recv(4096)
                    if not data:
                        return
                    
                    if sock is client:
                        # Cliente -> Remoto (REQUEST)
                        remote.sendall(data)
                        conn_info['bytes_sent'] += len(data)
                        self._intercept_data(data, 'REQUEST', conn_info)
                    else:
                        # Remoto -> Cliente (RESPONSE)
                        client.sendall(data)
                        conn_info['bytes_recv'] += len(data)
                        self._intercept_data(data, 'RESPONSE', conn_info)
                        
        except (socket.error, ConnectionResetError):
            pass
        except Exception as e:
            logger.error(f"Erro no tunelamento: {e}")
    
    def _intercept_data(self, data: bytes, direction: str, conn_info: dict):
        """
        Intercepta e analisa dados em tempo real
        Aqui você pode modificar, logar ou bloquear dados
        """
        dst_addr, dst_port = conn_info['dst']
        
        # Log de tráfego (limitado para não sobrecarregar)
        if len(self.traffic_logs) < 10000:
            log = TrafficLog(
                timestamp=datetime.now().isoformat(),
                app_name="unknown",  # Pode ser detectado via PID/porta
                src_addr=conn_info['addr'][0],
                dst_addr=dst_addr,
                dst_port=dst_port,
                bytes_sent=len(data) if direction == 'REQUEST' else 0,
                bytes_received=len(data) if direction == 'RESPONSE' else 0,
                protocol=self._detect_protocol(data, dst_port)
            )
            self.traffic_logs.append(log)
        
        # 🎯 AQUI VOCÊ PODE MODIFICAR OS DADOS
        # Exemplo: Modificar headers HTTP
        if direction == 'REQUEST' and b'HTTP' in data[:20]:
            # Injeta header customizado
            if b'\r\n\r\n' in data:
                modified = data.replace(b'\r\n\r\n', b'\r\nX-Intercepted: VPN-Proxy\r\n\r\n')
                return modified
        
        # Exemplo: Bloquear sites específicos
        # if b'facebook.com' in data:
        #     return None  # Bloqueia
        
        return data
    
    def _detect_protocol(self, data: bytes, port: int) -> str:
        """Detecta protocolo baseado na porta e conteúdo"""
        protocol_map = {
            80: 'HTTP',
            443: 'HTTPS',
            22: 'SSH',
            53: 'DNS',
        }
        
        if port in protocol_map:
            return protocol_map[port]
        
        # Detecção por conteúdo
        if data[:4] == b'\x16\x03\x01\x02':  # TLS handshake
            return 'TLS/SSL'
        elif b'HTTP' in data[:20]:
            return 'HTTP'
        
        return 'UNKNOWN'
    
    def _close_connection(self, client: socket.socket):
        """Fecha conexão e limpa recursos"""
        if client in self.connections:
            conn_info = self.connections[client]
            
            # Salva estatísticas
            duration = (datetime.now() - conn_info['start_time']).total_seconds()
            self.stats['active_connections'] -= 1
            self.stats['bytes_transferred'] += conn_info['bytes_sent'] + conn_info['bytes_recv']
            
            logger.info(f"❌ Conexão fechada: {conn_info['addr'][0]} -> {conn_info['dst'][0]}:{conn_info['dst'][1]} "
                       f"(Duração: {duration:.1f}s, Enviado: {conn_info['bytes_sent']}, Recebido: {conn_info['bytes_recv']})")
            
            # Fecha sockets
            try:
                conn_info['remote'].close()
            except:
                pass
            
            del self.connections[client]
        
        try:
            client.close()
        except:
            pass
        
        # Salva logs periodicamente
        if len(self.traffic_logs) % 100 == 0:
            self._save_logs()
    
    def _save_logs(self):
        """Salva logs de tráfego em JSON"""
        try:
            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump([asdict(log) for log in self.traffic_logs], f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Erro ao salvar logs: {e}")
    
    def stop(self):
        """Para o servidor"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        # Fecha todas as conexões ativas
        for client in list(self.connections.keys()):
            self._close_connection(client)
        
        self._save_logs()
        logger.info("👋 VPN Proxy encerrado. Logs salvos.")


class AppLauncher:
    """
    Lança aplicativos configurados automaticamente para usar o proxy
    Sem necessidade de configurar manualmente cada app
    """
    
    @staticmethod
    def launch_browser(proxy_host: str = '127.0.0.1', proxy_port: int = 1080):
        """Lança Chrome/Chromium com proxy configurado"""
        import subprocess
        import platform
        
        system = platform.system()
        
        # Argumentos para forçar uso do proxy SOCKS5
        proxy_arg = f'--proxy-server=socks5://{proxy_host}:{proxy_port}'
        ignore_cert = '--ignore-certificate-errors'  # Para HTTPS interception
        disable_quic = '--disable-quic'
        
        chrome_paths = {
            'Windows': [
                r'C:\Program Files\Google\Chrome\Application\chrome.exe',
                r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
                r'%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe'
            ],
            'Darwin': [  # macOS
                '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
                '/Applications/Chromium.app/Contents/MacOS/Chromium'
            ],
            'Linux': [
                '/usr/bin/google-chrome',
                '/usr/bin/google-chrome-stable',
                '/usr/bin/chromium',
                '/usr/bin/chromium-browser'
            ]
        }
        
        paths = chrome_paths.get(system, [])
        
        for path in paths:
            if os.path.exists(path):
                try:
                    subprocess.Popen([path, proxy_arg, ignore_cert, disable_quic, '--incognito'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    logger.info(f"🌐 Chrome lançado com VPN Proxy: {path}")
                    return True
                except Exception as e:
                    logger.error(f"Erro ao lançar Chrome: {e}")
        
        logger.warning("⚠️ Chrome não encontrado. Instale-o ou configure manualmente.")
        return False
    
    @staticmethod
    def launch_terminal(proxy_host: str = '127.0.0.1', proxy_port: int = 1080):
        """Lança terminal com variáveis de proxy configuradas"""
        import subprocess
        import platform
        
        env = os.environ.copy()
        env['ALL_PROXY'] = f'socks5://{proxy_host}:{proxy_port}'
        env['HTTP_PROXY'] = f'http://{proxy_host}:{proxy_port}'
        env['HTTPS_PROXY'] = f'http://{proxy_host}:{proxy_port}'
        
        system = platform.system()
        
        try:
            if system == 'Windows':
                # PowerShell com proxy configurado
                subprocess.Popen(['powershell', '-NoExit', '-Command', 
                                f'$env:ALL_PROXY="socks5://{proxy_host}:{proxy_port}"; '
                                f'$env:HTTP_PROXY="http://{proxy_host}:{proxy_port}"; '
                                f'$env:HTTPS_PROXY="http://{proxy_host}:{proxy_port}"; '
                                'Write-Host "VPN Proxy ativo no terminal" -ForegroundColor Green'],
                               env=env)
            elif system == 'Darwin':
                subprocess.Popen(['osascript', '-e', 
                                f'tell application "Terminal" to do script "export ALL_PROXY=socks5://{proxy_host}:{proxy_port}; echo VPN Proxy ativo"'])
            else:  # Linux
                terminals = ['gnome-terminal', 'konsole', 'xterm', 'terminator']
                for term in terminals:
                    if subprocess.run(['which', term], capture_output=True).returncode == 0:
                        if term == 'gnome-terminal':
                            subprocess.Popen([term, '--', 'bash', '-c', 
                                            f'export ALL_PROXY=socks5://{proxy_host}:{proxy_port}; echo "VPN Proxy ativo"; bash'],
                                           env=env)
                        else:
                            subprocess.Popen([term], env=env)
                        break
            
            logger.info("💻 Terminal lançado com VPN Proxy configurado")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao lançar terminal: {e}")
            return False
    
    @staticmethod
    def get_proxy_env_vars(proxy_host: str = '127.0.0.1', proxy_port: int = 1080) -> Dict[str, str]:
        """Retorna variáveis de ambiente para configurar manualmente apps"""
        return {
            'ALL_PROXY': f'socks5://{proxy_host}:{proxy_port}',
            'http_proxy': f'http://{proxy_host}:{proxy_port}',
            'https_proxy': f'http://{proxy_host}:{proxy_port}',
            'HTTP_PROXY': f'http://{proxy_host}:{proxy_port}',
            'HTTPS_PROXY': f'http://{proxy_host}:{proxy_port}',
            'SOCKS_SERVER': f'{proxy_host}:{proxy_port}',
            'SOCKS_VERSION': '5'
        }


def print_setup_instructions(proxy_host: str, proxy_port: int):
    """Imprime instruções de configuração para vários apps"""
    print("\n" + "="*60)
    print("📖 INSTRUÇÕES DE CONFIGURAÇÃO MANUAL")
    print("="*60)
    
    print(f"\n🌐 NAVEGADORES (Configure manualmente):")
    print(f"   Host: {proxy_host}")
    print(f"   Porta: {proxy_port}")
    print(f"   Protocolo: SOCKS5")
    
    print(f"\n📱 APLICATIVOS QUE SUPORTAM PROXY:")
    print("   Telegram: Configurações > Dados > Proxy > SOCKS5")
    print("   Discord: Configurações > Proxy > SOCKS5")
    print("   curl: curl --socks5-hostname {host}:{port} url")
    print("   git: git config --global http.proxy socks5://{host}:{port}")
    print("   npm: npm config set proxy http://{host}:{port}")
    print("   Python requests: proxies={'http': 'socks5://{host}:{port}'}")
    
    print(f"\n🔧 VARIÁVEIS DE AMBIENTE (para apps em terminal):")
    env_vars = AppLauncher.get_proxy_env_vars(proxy_host, proxy_port)
    for key, value in env_vars.items():
        print(f"   export {key}={value}")
    
    print(f"\n⚡ DICA: Use --launch-chrome ou --launch-terminal para auto-configurar!")
    print("="*60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description='GitHub VPN Proxy - Funciona sem permissão de administrador',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # Iniciar proxy básico
  python vpn_proxy.py
  
  # Iniciar e lançar Chrome configurado automaticamente
  python vpn_proxy.py --launch-chrome
  
  # Iniciar e lançar terminal configurado
  python vpn_proxy.py --launch-terminal
  
  # Porta customizada
  python vpn_proxy.py --port 9090 --launch-chrome
  
  # Modo silencioso (apenas logs em arquivo)
  python vpn_proxy.py --quiet
        """
    )
    
    parser.add_argument('--host', default='127.0.0.1', help='Host do proxy (padrão: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=1080, help='Porta do proxy (padrão: 1080)')
    parser.add_argument('--launch-chrome', action='store_true', help='Lança Chrome configurado automaticamente')
    parser.add_argument('--launch-terminal', action='store_true', help='Lança terminal configurado automaticamente')
    parser.add_argument('--quiet', action='store_true', help='Modo silencioso')
    
    args = parser.parse_args()
    
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    
    # Cria e inicia o servidor VPN Proxy
    server = SOCKS5Server(host=args.host, port=args.port)
    
    # Inicia em thread separada para não bloquear
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    
    # Aguarda servidor iniciar
    import time
    time.sleep(1)
    
    # Lança aplicativos configurados
    if args.launch_chrome:
        AppLauncher.launch_browser(args.host, args.port)
    
    if args.launch_terminal:
        AppLauncher.launch_terminal(args.host, args.port)
    
    # Se não lançou nada, mostra instruções
    if not args.launch_chrome and not args.launch_terminal:
        print_setup_instructions(args.host, args.port)
    
    # Mantém programa rodando
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Encerrando...")
        server.stop()


if __name__ == "__main__":
    main()
