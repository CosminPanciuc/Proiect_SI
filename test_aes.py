import os
import sys
from pathlib import Path
from aes import *


def parse_rsp_file(file_path):
    tests = []
    current_test = {}
    current_section = None
    
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
                
            if line.startswith('['):
                current_section = line[1:-1].upper()
                continue
                
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'COUNT':
                    if current_test:
                        tests.append((current_section, current_test))
                    current_test = {'COUNT': value}
                else:
                    current_test[key] = value
    
    if current_test:
        tests.append((current_section, current_test))
        
    return tests

def run_kat_tests(test_files):
    total_passed = 0
    total_failed = 0
    
    for test_file in test_files:
        print(f"\nTesting file: {test_file.name}")
        file_passed = 0
        file_failed = 0
        
        tests = parse_rsp_file(test_file)
        
        for section, test in tests:
            if section not in ['ENCRYPT', 'DECRYPT']:
                continue
                
            try:
                key = bytes.fromhex(test['KEY'])
                if 'IV' in test:
                    iv = bytes.fromhex(test['IV'])
                
                if section == 'ENCRYPT':
                    plaintext = bytes.fromhex(test['PLAINTEXT'])
                    expected = bytes.fromhex(test['CIPHERTEXT'])
                    
                    if 'IV' in test:
                        result = encrypt_block(plaintext, expand_key(key))
                    else:
                        if len(plaintext) == 16:
                            result = encrypt_block(plaintext, expand_key(key))
                        else:
                            result = encrypt_ecb(plaintext, key)
                    
                    if result == expected:
                        file_passed += 1
                    else:
                        file_failed += 1
                        print(f"❌ FAIL {test['COUNT']} {section}")
                        print(f"  Key:    {test['KEY']}")
                        print(f"  Input:  {test['PLAINTEXT']}")
                        print(f"  Expect: {expected.hex()}")
                        print(f"  Got:    {result.hex()}")
                        
                elif section == 'DECRYPT':
                    ciphertext = bytes.fromhex(test['CIPHERTEXT'])
                    expected = bytes.fromhex(test['PLAINTEXT'])
                    
                    if 'IV' in test:
                        result = decrypt_block(ciphertext, expand_key(key))  
                    else:
                        if len(ciphertext) == 16:
                            result = decrypt_block(ciphertext, expand_key(key))
                        else:
                            result = decrypt_ecb(ciphertext, key)
                    
                    if result == expected:
                        file_passed += 1
                    else:
                        file_failed += 1
                        print(f"❌ FAIL {test['COUNT']} {section}")
                        print(f"  Key:    {test['KEY']}")
                        print(f"  Input:  {test['CIPHERTEXT']}")
                        print(f"  Expect: {expected.hex()}")
                        print(f"  Got:    {result.hex()}")
                        
            except Exception as e:
                file_failed += 1
                print(f"⚠️ Error processing test {test.get('COUNT', '?')}: {str(e)}")
                continue
                
        print(f"  Results: {file_passed} passed, {file_failed} failed")
        total_passed += file_passed
        total_failed += file_failed
        
    return total_passed, total_failed

def main():
    test_dir = Path('Test')
        
    test_files = list(test_dir.glob('*.rsp'))
    if not test_files:
        print("Error: No .rsp files found in 'test' directory!")
        sys.exit(1)
        
    print("\nRunning NIST KAT tests...")
    passed, failed = run_kat_tests(test_files)
    
    print("\nFinal Results:")
    print(f"Total tests passed: {passed}")
    print(f"Total tests failed: {failed}")
    
    if failed > 0:
        print("\n⚠️ Some tests failed! Check your implementation.")
        sys.exit(1)
    else:
        print("\n✅ All tests passed!")
        sys.exit(0)

if __name__ == "__main__":
    main()