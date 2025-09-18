class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_BLUE = '\033[44m'

def show_banner():
    gradient_colors = [
        '\033[38;5;196m',  # Bright red
        '\033[38;5;202m',  # Orange
        '\033[38;5;208m',  # Dark orange
        '\033[38;5;214m',  # Yellow-orange
        '\033[38;5;220m',  # Yellow
        '\033[38;5;154m',  # Light green
        '\033[38;5;118m',  # Green
        '\033[38;5;82m',   # Bright green
        '\033[38;5;46m',   # Lime green
        '\033[38;5;51m'    # Cyan
    ]
    
    banner_lines = [
        "  _    _             _              ",
        " | |  | |           | |             ",
        " | |__| | ___   ___ | | __ _   _    ",
        " |  __  |/ _ \\ / _ \\| |/ /| | | |   ",
        " | |  | | (_) | (_) |   < | |_| |_  ",
        " |_|  |_|\\___/ \\___/|_|\\_\\ \\__, (_) ",
        "                           __/ |   ",
        "                          |___/    ",
        "                                   ",
        "           ~ by dado1513            "
    ]
    
    print()
    for line, color in zip(banner_lines, gradient_colors):
        print(f"{color}{Colors.BOLD}{line}{Colors.RESET}")
    print()
