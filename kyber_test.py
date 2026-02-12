try:
    from kyber import Kyber768
    print("Kyber is installed and working!")
except Exception as e:
    print(f"Kyber error: {e}")