import os

# Folders we want to skip completely
SKIP_FOLDERS = ['.git', '__pycache__', 'venv', '.pytest_cache']
# Files we don't need to read
SKIP_FILES = ['dump.py']

print("--- START OF PROJECT DUMP ---")

for root, dirs, files in os.walk('.'):
    # Modify dirs in-place to skip unwanted folders
    dirs[:] = [d for d in dirs if d not in SKIP_FOLDERS]
    
    for file in files:
        if file in SKIP_FILES:
            continue
            
        file_path = os.path.join(root, file)
        print(f"=== FILE: {file_path} ===")
        
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                print(f.read())
        except Exception as e:
            print(f"[ERROR READING FILE: {e}]")
            
        print("=== END ===\n")

print("--- END OF PROJECT DUMP ---")