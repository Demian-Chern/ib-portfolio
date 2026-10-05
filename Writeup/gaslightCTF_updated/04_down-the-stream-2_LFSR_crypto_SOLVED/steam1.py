def next_register(register: int) -> int:
    for _ in range(8):
        feedback = (((register >> 7) & 1) ^
                    ((register >> 5) & 1) ^
                    ((register >> 4) & 1) ^
                    ((register >> 3) & 1))
        register = ((register << 1) | feedback) & 0xff
    return register

# 1. Загружаем шифртекст
ct_hex = "e944b3a55e47c5d8f3af3c93e2f7f2b1892094001e95a16b779b907bd374e2327a2dace45d222f69138b"
ct = bytes.fromhex(ct_hex)

# 2. Перебираем все возможные значения IV (от 0 до 255)
for iv in range(256):
    register = iv
    pt = bytearray()
    
    # Генерируем гамму и расшифровываем
    for i in range(len(ct)):
        pt.append(ct[i] ^ register)
        register = next_register(register)
        
    # 3. Пытаемся декодировать результат в текст и ищем флаг
    try:
        pt_str = pt.decode('ascii')
        # Ищем стандартные маркеры флагов
        if 'CTF{' in pt_str or 'flag{' in pt_str.lower():
            print(f"Найден IV (hex): {hex(iv)}")
            print(f"Флаг: {pt_str}")
    except:
        pass # Игнорируем, если байты не складываются в ASCII