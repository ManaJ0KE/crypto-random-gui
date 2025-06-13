import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
import time
import hashlib
import secrets
import random
from collections import defaultdict
import os
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from scipy.stats import gaussian_kde
import numpy as np

try:
    import ctypes
except ImportError:
    ctypes = None


class CryptoRandomGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("МУтант")
        self.geometry("1400x800")
        self.resizable(True, True)

        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        self.style.configure("TLabel", font=("Segoe UI", 11))
        self.style.configure("TButton", font=("Segoe UI Semibold", 11), padding=6)
        self.style.configure("TEntry", font=("Segoe UI", 11))
        self.style.configure("TCombobox", font=("Segoe UI", 11))
        self.style.configure("Stats.TLabel", font=("Segoe UI Semibold", 12))
        self.style.configure("Log.TLabel", font=("Consolas", 10))

        self.distribution = defaultdict(int)
        self.running = False
        self.thread = None
        self.prev_hash = b''
        self.counter = 0
        self.signature_log = []

        self.all_plot_types = [
            "Гистограмма",
            "Плотность KDE",
            "Скользящее окно",
            "Круговая диаграмма",
            "Ящик с усами",
            "Линейный график",
            "Столбчатый по уникальным",
            "Диаграмма рассеяния",
            "График суммы",
            "График изменений"
        ]

        self.create_widgets()
        self.create_main_plot()

    def create_widgets(self):
        frm = ttk.LabelFrame(self, text="Параметры генерации", padding=15)
        frm.pack(padx=15, pady=10, fill=tk.X)

        ttk.Label(frm, text="Минимум:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5), pady=5)
        self.min_entry = ttk.Entry(frm, width=10)
        self.min_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        self.min_entry.insert(0, "1")

        ttk.Label(frm, text="Максимум:").grid(row=0, column=2, sticky=tk.W, padx=(15, 5), pady=5)
        self.max_entry = ttk.Entry(frm, width=10)
        self.max_entry.grid(row=0, column=3, sticky=tk.W, pady=5)
        self.max_entry.insert(0, "10")

        ttk.Label(frm, text="Задержка (сек):").grid(row=0, column=4, sticky=tk.W, padx=(15, 5), pady=5)
        self.delay_entry = ttk.Entry(frm, width=10)
        self.delay_entry.grid(row=0, column=5, sticky=tk.W, pady=5)
        self.delay_entry.insert(0, "1.0")

        ttk.Label(frm, text="Усиление энтропии:").grid(row=0, column=6, sticky=tk.W, padx=(15, 5), pady=5)
        self.entropy_strength_entry = ttk.Entry(frm, width=6)
        self.entropy_strength_entry.grid(row=0, column=7, sticky=tk.W, pady=5)
        self.entropy_strength_entry.insert(0, "1")

        self.start_btn = ttk.Button(frm, text="Запустить", command=self.toggle_run)
        self.start_btn.grid(row=0, column=8, sticky=tk.W, padx=(30, 0), pady=5)

        self.clear_btn = ttk.Button(frm, text="Очистить", command=self.clear_data)
        self.clear_btn.grid(row=0, column=9, sticky=tk.W, padx=(10, 0), pady=5)

        self.verify_btn = ttk.Button(frm, text="Проверить подлинность", command=self.verify_signatures)
        self.verify_btn.grid(row=0, column=10, sticky=tk.W, padx=(10, 0), pady=5)

        ttk.Label(frm, text="Выбор графика:").grid(row=1, column=0, sticky=tk.W, pady=(10,0), padx=(0,5))
        self.plot_selector = ttk.Combobox(frm, values=self.all_plot_types, state="readonly", width=25)
        self.plot_selector.grid(row=1, column=1, columnspan=3, sticky=tk.W, pady=(10,0))
        self.plot_selector.current(0)
        self.plot_selector.bind("<<ComboboxSelected>>", lambda e: self.update_main_plot())

        stats_frame = ttk.LabelFrame(self, text="Статистика", padding=10)
        stats_frame.pack(fill=tk.X, padx=15, pady=10)

        self.total_label = ttk.Label(stats_frame, text="Всего сгенерировано: 0", style="Stats.TLabel")
        self.total_label.pack(side=tk.LEFT, padx=(10, 40))

        self.unique_label = ttk.Label(stats_frame, text="Уникальных чисел: 0", style="Stats.TLabel")
        self.unique_label.pack(side=tk.LEFT)

        log_frame = ttk.LabelFrame(self, text="Журнал генерации", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

        self.log = ScrolledText(log_frame, height=12, font=("Consolas", 11), state='disabled', bg="#f9f9f9")
        self.log.pack(fill=tk.BOTH, expand=True)

    def create_main_plot(self):
        self.fig, self.ax = plt.subplots(figsize=(10, 4))
        self.ax.set_title("Гистограмма значений")
        self.ax.set_xlabel("Число")
        self.ax.set_ylabel("Частота")

        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().pack(padx=15, pady=(0, 15), fill=tk.BOTH, expand=False)

    def log_message(self, msg):
        self.log.configure(state='normal')
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)
        self.log.configure(state='disabled')

    def clear_data(self):
        if self.running:
            messagebox.showwarning("Внимание", "Остановите генерацию перед очисткой данных.")
            return
        self.distribution.clear()
        self.prev_hash = b''
        self.counter = 0
        self.signature_log.clear()
        self.update_stats()
        self.log.configure(state='normal')
        self.log.delete(1.0, tk.END)
        self.log.configure(state='disabled')
        self.update_main_plot()

    def toggle_run(self):
        if self.running:
            self.running = False
            self.start_btn.config(text="Запустить")
            self.enable_inputs(True)
        else:
            try:
                self.min_val = int(self.min_entry.get())
                self.max_val = int(self.max_entry.get())
                if self.min_val > self.max_val:
                    messagebox.showerror("Ошибка", "Минимум не может быть больше максимума.")
                    return
                self.delay = float(self.delay_entry.get())
                if self.delay < 0:
                    messagebox.showerror("Ошибка", "Задержка не может быть отрицательной.")
                    return
                self.entropy_strength = int(self.entropy_strength_entry.get())
                if self.entropy_strength < 1:
                    messagebox.showerror("Ошибка", "Усиление энтропии должно быть >= 1.")
                    return
            except ValueError:
                messagebox.showerror("Ошибка", "Проверьте правильность введённых данных.")
                return

            self.running = True
            self.start_btn.config(text="Остановить")
            self.enable_inputs(False)
            self.thread = threading.Thread(target=self.generator_loop, daemon=True)
            self.thread.start()

    def enable_inputs(self, enable=True):
        state = "normal" if enable else "disabled"
        self.min_entry.config(state=state)
        self.max_entry.config(state=state)
        self.delay_entry.config(state=state)
        self.entropy_strength_entry.config(state=state)
        self.clear_btn.config(state=state)
        self.verify_btn.config(state=state)
        self.plot_selector.config(state=state)

    def collect_entropy_heavy(self, previous_hash=None, strength=1):
        data = bytearray()
        data.extend(os.urandom(128 * strength))
        data.extend(str(time.time_ns()).encode())
        data.extend(str(time.perf_counter_ns()).encode())
        data.extend(str(time.process_time_ns()).encode())

        for _ in range(300 * strength):
            data.extend(str(random.random()).encode())
        for _ in range(150 * strength):
            data.extend(str(secrets.randbelow(2 ** 64)).encode())

        for _ in range(100 * strength):
            n = random.randint(10, 500)
            s = 0
            for i in range(n):
                s += (i ** 3 + random.randint(0, 1000)) % (n + 1)
            data.extend(str(s).encode())

        for _ in range(30 * strength):
            start = time.perf_counter_ns()
            end = start
            while end - start < random.randint(50000, 200000):
                end = time.perf_counter_ns()
            data.extend(str(end - start).encode())

        dummy = object()
        data.extend(str(id(dummy)).encode())
        data.extend(str(threading.get_ident()).encode())
        data.extend(str(os.getpid()).encode())
        if os.name == "nt" and ctypes:
            try:
                data.extend(str(ctypes.windll.kernel32.GetTickCount64()).encode())
            except Exception:
                pass

        if previous_hash:
            data.extend(previous_hash)

        h1 = hashlib.sha512(data).digest()
        h2 = hashlib.sha3_512(h1 + data).digest()
        h3 = hashlib.blake2b(h2 + h1).digest()

        for _ in range(5):
            rnd_bytes = os.urandom(64)
            h3 = hashlib.sha512(h3 + rnd_bytes).digest()

        return h3

    def generate_secure_number(self, min_val, max_val, prev_hash, entropy_strength=1):
        entropy_hash = self.collect_entropy_heavy(prev_hash, strength=entropy_strength)
        system_rand = secrets.token_bytes(8)
        mixed_bytes = bytes(a ^ b for a, b in zip(entropy_hash[:8], system_rand))
        shifted_bytes = mixed_bytes[4:] + mixed_bytes[:4]
        rand_int = int.from_bytes(shifted_bytes, "big")
        rand = min_val + (rand_int % (max_val - min_val + 1))
        current_hash = hashlib.sha512(str(rand).encode() + prev_hash).digest()
        return rand, current_hash

    def update_stats(self):
        total = sum(self.distribution.values())
        unique = len([k for k, v in self.distribution.items() if v > 0])
        self.total_label.config(text=f"Всего сгенерировано: {total}")
        self.unique_label.config(text=f"Уникальных чисел: {unique}")

    def update_main_plot(self):
        self.ax.clear()
        plot_type = self.plot_selector.get()
        vals = list(range(self.min_val, self.max_val + 1))
        all_numbers = []
        for v in vals:
            all_numbers.extend([v] * self.distribution[v])

        self.ax.set_title(plot_type)

        if plot_type == "Гистограмма":
            if len(all_numbers) == 0:
                self.ax.text(0.5, 0.5, "Нет данных", ha="center", va="center")
            else:
                self.ax.hist(all_numbers, bins=range(self.min_val, self.max_val + 2), color='skyblue', edgecolor='black')

        elif plot_type == "Плотность KDE":
            if len(all_numbers) < 2:
                self.ax.text(0.5, 0.5, "Недостаточно данных", ha="center", va="center")
            else:
                kde = gaussian_kde(all_numbers)
                x = np.linspace(self.min_val, self.max_val, 500)
                self.ax.plot(x, kde(x), color='darkgreen')

        elif plot_type == "Скользящее окно":
            window_size = 20
            if len(all_numbers) >= window_size:
                moving_avg = np.convolve(all_numbers, np.ones(window_size) / window_size, mode='valid')
                self.ax.plot(moving_avg, color="purple")
                self.ax.set_xlabel("Индекс")
                self.ax.set_ylabel("Скользящее среднее")
            else:
                self.ax.text(0.5, 0.5, "Недостаточно данных", ha="center", va="center")

        elif plot_type == "Круговая диаграмма":
            if len(all_numbers) == 0:
                self.ax.text(0.5, 0.5, "Нет данных", ha="center", va="center")
            else:
                labels = [str(v) for v in vals if self.distribution[v] > 0]
                sizes = [self.distribution[v] for v in vals if self.distribution[v] > 0]
                if sizes:
                    self.ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=plt.cm.Paired.colors)
                else:
                    self.ax.text(0.5, 0.5, "Нет данных", ha="center", va="center")

        elif plot_type == "Ящик с усами":
            if len(all_numbers) >= 4:
                self.ax.boxplot(all_numbers, vert=True, patch_artist=True,
                               boxprops=dict(facecolor='skyblue', color='blue'),
                               medianprops=dict(color='red'))
                self.ax.set_ylabel("Значение")
            else:
                self.ax.text(0.5, 0.5, "Недостаточно данных", ha="center", va="center")

        elif plot_type == "Линейный график":
            if len(all_numbers) == 0:
                self.ax.text(0.5, 0.5, "Нет данных", ha="center", va="center")
            else:
                self.ax.plot(all_numbers, color='teal')
                self.ax.set_xlabel("Индекс")
                self.ax.set_ylabel("Значение")

        elif plot_type == "Столбчатый по уникальным":
            unique_vals = sorted(set(all_numbers))
            counts = [self.distribution[v] for v in unique_vals]
            self.ax.bar(unique_vals, counts, color='orange')
            self.ax.set_xlabel("Значение")
            self.ax.set_ylabel("Частота")

        elif plot_type == "Диаграмма рассеяния":
            if len(all_numbers) >= 2:
                y_vals = np.random.normal(0, 1, size=len(all_numbers))
                self.ax.scatter(all_numbers, y_vals, color='navy', alpha=0.5)
                self.ax.set_xlabel("Значение")
                self.ax.set_ylabel("Случайное")
            else:
                self.ax.text(0.5, 0.5, "Недостаточно данных", ha="center", va="center")

        elif plot_type == "График суммы":
            if len(all_numbers) > 0:
                cumsum = np.cumsum(all_numbers)
                self.ax.plot(cumsum, color='brown')
                self.ax.set_xlabel("Индекс")
                self.ax.set_ylabel("Сумма")
            else:
                self.ax.text(0.5, 0.5, "Нет данных", ha="center", va="center")

        elif plot_type == "График изменений":
            if len(all_numbers) > 1:
                diffs = np.diff(all_numbers)
                self.ax.plot(diffs, color='darkred')
                self.ax.set_xlabel("Индекс")
                self.ax.set_ylabel("Изменение")
            else:
                self.ax.text(0.5, 0.5, "Недостаточно данных", ha="center", va="center")

        self.canvas.draw_idle()

    def generator_loop(self):
        while self.running:
            num, self.prev_hash = self.generate_secure_number(
                self.min_val,
                self.max_val,
                self.prev_hash,
                entropy_strength=self.entropy_strength
            )
            self.distribution[num] += 1
            self.signature_log.append((num, self.prev_hash.hex()))
            self.counter += 1
            self.log_message(f"#{self.counter}: {num} | Хэш: {self.prev_hash.hex()[:16]}...")
            self.update_stats()
            self.update_main_plot()
            time.sleep(self.delay)

    def verify_signatures(self):
        invalid = 0
        prev_hash = b''
        for i, (num, hsh_hex) in enumerate(self.signature_log):
            num_bytes = str(num).encode()
            expected_hash = hashlib.sha512(num_bytes + prev_hash).digest()
            if expected_hash.hex() != hsh_hex:
                invalid += 1
            prev_hash = bytes.fromhex(hsh_hex)
        if invalid == 0:
            messagebox.showinfo("Проверка", "Все подписи валидны.")
        else:
            messagebox.showwarning("Проверка", f"Найдено {invalid} неверных подписей.")

if __name__ == "__main__":
    app = CryptoRandomGUI()
    app.mainloop()
