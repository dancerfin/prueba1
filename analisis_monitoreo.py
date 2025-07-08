#!/usr/bin/env python3
import re
import matplotlib.pyplot as plt
from datetime import datetime

def parse_log_file(log_file):
    pattern = r".*Monitor Rate: (\d+\.\d+)%.*Processed: (\d+).*Total: (\d+).*Elapsed: (\d+\.\d+)s"
    data = []
    
    with open(log_file, 'r') as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                rate = float(match.group(1))
                processed = int(match.group(2))
                total = int(match.group(3))
                elapsed = float(match.group(4))
                data.append({
                    'rate': rate,
                    'processed': processed,
                    'total': total,
                    'elapsed': elapsed
                })
    
    return data

def generate_report(data):
    if not data:
        print("No se encontraron datos de monitoreo")
        return
    
    rates = [d['rate'] for d in data]
    times = [d['elapsed'] for d in data]
    
    avg_rate = sum(rates) / len(rates)
    min_rate = min(rates)
    max_rate = max(rates)
    
    print("\n=== Reporte de Monitoreo ===")
    print(f"Tasa promedio: {avg_rate:.2f}%")
    print(f"Tasa mínima: {min_rate:.2f}%")
    print(f"Tasa máxima: {max_rate:.2f}%")
    print(f"Duración total: {times[-1]:.1f} segundos")
    print(f"Eventos procesados: {data[-1]['processed']}")
    print(f"Eventos totales: {data[-1]['total']}")
    
    # Gráfico
    plt.figure(figsize=(10, 5))
    plt.plot(times, rates, 'b-', label='Tasa de monitoreo')
    plt.axhline(y=99.9, color='r', linestyle='--', label='Objetivo (99.9%)')
    plt.title('Tasa de Monitoreo en Tiempo Real')
    plt.xlabel('Tiempo (segundos)')
    plt.ylabel('Porcentaje de eventos monitoreados (%)')
    plt.ylim(90, 101)
    plt.grid(True)
    plt.legend()
    plt.savefig('monitoring_rate.png')
    print("\nGráfico guardado como 'monitoring_rate.png'")

if __name__ == '__main__':
    log_file = input("Ingrese la ruta del archivo de log (ryu.log): ").strip()
    data = parse_log_file(log_file)
    generate_report(data)