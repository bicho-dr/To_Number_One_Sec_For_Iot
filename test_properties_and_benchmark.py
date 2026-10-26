def run_benchmark():
    print("[*] Running Benchmarking (Signing time, Verification time, Size vs Ring Size n)...")
    message = b"Benchmark Message"
    ring_sizes = [2, 8, 32, 128]
    
    print(f"{'Ring Size (n)':<15} | {'Sign Time (ms)':<18} | {'Verify Time (ms)':<18} | {'Size (Bytes)':<15}")
    print("-" * 75)
    
    for n in ring_sizes:
        # توليد المفاتيح للحلقة بالحجم الحالي
        keys = [keygen() for _ in range(n)]
        sk_list = [k[0] for k in keys]
        pk_list = [k[1] for k in keys]
        signer_idx = 0
        
        # قياس زمن التوقيع
        start_time = time.perf_counter()
        signature = ring_sign(message, pk_list, signer_idx, sk_list[signer_idx])
        end_time = time.perf_counter()
        sign_time_ms = (end_time - start_time) * 1000
        
        # قياس زمن التحقق
        start_time = time.perf_counter()
        res = ring_verify(message, pk_list, signature)
        end_time = time.perf_counter()
        verify_time_ms = (end_time - start_time) * 1000
        
        assert res, f"Verification failed for n={n}"
        
        # تقدير حجم التوقيع (بايتس): يعتمد على حجم الحلقة n
        sig_size_bytes = 32 + (n * 32)
        
        print(f"{n:<15} | {sign_time_ms:<18.4f} | {verify_time_ms:<18.4f} | {sig_size_bytes:<15}")

    print("-" * 75)
    print("[+] Benchmarking completed successfully!\n")