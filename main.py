# main.py
import os
from core import scanner, osint, brute
from utils import reporter

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    print("""
   ███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗  ╗██╗  ██╗  
   ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗  ╚██╗██╔╝  
   ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝   ╚███╔╝ 
   ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔═══╝    ██╔██╗
   ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║       ██╔╝ ██╗ 
   ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝       ╚═╝  ╚═╝
            by Scarlet | Recon & OSINT Toolkit
    """)

def main():
    while True:
        clear()
        print_banner()
        print("""
[1] Technical Recon (ReconWarden X)
[2] OSINT Toolkit
[3] Generate Report
[4] Brute-Force
[5] Exit
        """)
        choice = input("Select an option: ").strip()

        if choice == '1':
            scanner.run()
        elif choice == '2':
            osint.run()
        elif choice == '3':
            reporter.run()
        elif choice == '4':
            brute.run()
        elif choice == '5':
            print("Goodbye.")
            break
        else:
            input("Invalid choice. Press Enter to try again.")

if __name__ == "__main__":
    main()
