import argparse
from scapy.all import rdpcap


def read_pcap(file):
    # Чтение pcap файла и возврат пакета
    return rdpcap(file)


def packets_match(pkt1, pkt2):
    # Проверка пакетов на совпадение
    return bytes(pkt1) == bytes(pkt2)


def find_matching_intervals(packets1, packets2, min_length):
    # Поиск совпадающих интервалов пакетов в двух списках пакетов
    intervals = []
    len1, len2 = len(packets1), len(packets2)

    i = 0
    while i < len1:
        for j in range(len2):
            match_length = 0
            while (i + match_length < len1 and j + match_length < len2 and
                   packets_match(packets1[i + match_length], packets2[j + match_length])):
                match_length += 1

            if match_length >= min_length:
                intervals.append((i, j, match_length))
                i += match_length - 1
                break
        i += 1

    return intervals


def display_intervals(intervals, packets1, packets2, details_interval):
    # Отображение информации о совпадающих интервалах
    print(f"Всего совпадающих интервалов: {len(intervals)}")
    for k, interval in enumerate(intervals):
        if details_interval == -1 or details_interval == k + 1:
            i, j, length = interval
            print(f"Интервал {k + 1}:")
            print(f"  Количество совпадающих пакетов: {length}")
            print(f"  Первый совпадающий пакет в pcap1: Индекс {i}, Временная метка {packets1[i].time}")
            print(f"  Первый совпадающий пакет в pcap2: Индекс {j}, Временная метка {packets2[j].time}")


def main():
    parser = argparse.ArgumentParser(description="Найти совпадающие интервалы в двух pcap файлах")
    parser.add_argument("pcap1", help="Первый pcap файл")
    parser.add_argument("pcap2", help="Второй pcap файл")
    parser.add_argument("--min-length", type=int, default=1, help="Минимальная длина совпадающих интервалов")
    parser.add_argument("--interval", type=int, default=1, help="Номер интервала для отображения информации")

    args = parser.parse_args()

    packets1 = read_pcap(args.pcap1)
    packets2 = read_pcap(args.pcap2)

    intervals = find_matching_intervals(packets1, packets2, args.min_length)
    display_intervals(intervals, packets1, packets2, args.interval - 1)


if __name__ == "__main__":
    main()
