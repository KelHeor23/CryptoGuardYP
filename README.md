### Команды для запуска приложения

```bash
cd build
echo "Hello OpenSSL crypto world!" > input.txt

./CryptoGuard -i input.txt     -o encrypted.txt -p 1234 --command encrypt
./CryptoGuard -i encrypted.txt -o decrypted.txt -p 1234 --command decrypt

./CryptoGuard -i input.txt     --command checksum
./CryptoGuard -i decrypted.txt --command checksum
```

### Команда для запуска тестов

```bash
cd build
./CryptoGuard_tests
```
