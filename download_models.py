# download_models.py
import os
import gdown

def download_models():
    """Download model files from Google Drive on startup"""
    
    # Your Google Drive file IDs
    models = {
        "modelparameters2.pkl": "1ldUskhi9X4J8R601mVZ-OQHL_IY3k1ZJ",
        "phishing_model.pkl": "1BfV3aQt_LcOyit2bNxepFx41Hh33eHI6"
    }
    
    print("=" * 50)
    print("Checking model files...")
    print("=" * 50)
    
    for filename, file_id in models.items():
        if os.path.exists(filename):
            file_size = os.path.getsize(filename) / (1024 * 1024)  # Size in MB
            print(f"✓ {filename} already exists ({file_size:.2f} MB)")
            continue
        
        print(f"⬇ Downloading {filename} from Google Drive...")
        try:
            url = f"https://drive.google.com/uc?id={file_id}"
            gdown.download(url, filename, quiet=False)
            file_size = os.path.getsize(filename) / (1024 * 1024)
            print(f"✓ Successfully downloaded {filename} ({file_size:.2f} MB)")
        except Exception as e:
            print(f"✗ Error downloading {filename}: {e}")
            raise
    
    print("=" * 50)
    print("✓ All models ready!")
    print("=" * 50)

if __name__ == "__main__":
    download_models()