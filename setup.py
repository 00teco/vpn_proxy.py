#!/usr/bin/env python3
"""
Setup do GitHub VPN Proxy
Instalação simples sem necessidade de admin
"""

import os
import sys
import stat

def setup():
    print("🚀 GitHub VPN Proxy - Instalação")
    print("=" * 50)
    
    # Verifica Python
    if sys.version_info < (3, 6):
        print("❌ Python 3.6+ necessário")
        sys.exit(1)
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detectado")
    
    # Torna executável (Unix)
    if os.name != 'nt':  # Não Windows
        script = 'vpn_proxy.py'
        if os.path.exists(script):
            st = os.stat(script)
            os.chmod(script, st.st_mode | stat.S_IEXEC)
            print("✅ Script tornado executável")
    
    # Cria diretório de logs
    os.makedirs('logs', exist_ok=True)
    
    print("\n" + "=" * 50)
    print("✅ Instalação concluída!")
    print("\n🎯 Uso rápido:")
    print("   python vpn_proxy.py --launch-chrome")
    print("   python vpn_proxy.py --launch-terminal")
    print("   python vpn_proxy.py --port 9090")
    print("\n📖 Leia o README.md para mais detalhes")

if __name__ == "__main__":
    setup()
