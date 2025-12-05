import tkinter as tk
import bcrypt

# --------- FUNCIONES DE ARCHIVO ---------

def cargar_datos():
    with open("datos.txt", "r") as archivo:
        linea = archivo.readline().strip()
        clave, valor = linea.split(":")
        return valor

def guardar_password(hashpw):
    with open("datos.txt", "w") as archivo:
        archivo.write(f"password:{hashpw}\n")

# --------- VENTANA PRINCIPAL ---------

ventana = tk.Tk()
ventana.title("Hasheador")

# --------- FUNCIONES DE INTERFAZ ---------

def mostrar_mensaje(texto):
    """Muestra un mensaje en la ventana"""
    limpiar_ventana()
    tk.Label(ventana, text=texto).grid(row=0, column=0, columnspan=2, pady=10)

def limpiar_ventana():
    """Elimina todos los widgets actuales"""
    for widget in ventana.winfo_children():
        widget.destroy()

def pedir_contraseña():
    """Pantalla para introducir contraseña"""
    limpiar_ventana()

    tk.Label(ventana, text="Introduce tu contraseña:").grid(row=0, column=0, columnspan=2, pady=10)
    entrada = tk.Entry(ventana, show="*")
    entrada.grid(row=1, column=0, columnspan=2)

    tk.Button(ventana, text="Aceptar",
              command=lambda: verificar_contraseña(entrada.get())
    ).grid(row=2, column=0, columnspan=2, pady=10)

def menu_cambio():
    """Pregunta si quiere cambiar la contraseña"""
    limpiar_ventana()

    tk.Label(ventana, text="¿Quieres cambiar la contraseña?").grid(
        row=0, column=0, columnspan=2, pady=10
    )

    tk.Button(
        ventana,
        text="Sí",
        command=pedir_nueva_contraseña
    ).grid(row=1, column=0, padx=10)

    tk.Button(
        ventana,
        text="No",
        command=lambda: (mostrar_mensaje("Saliendo..."), ventana.after(1500, ventana.destroy()))
    ).grid(row=1, column=1, padx=10)

def pedir_nueva_contraseña():
    """Pantalla para introducir nueva contraseña"""
    limpiar_ventana()

    tk.Label(ventana, text="Introduce la nueva contraseña:").grid(row=0, column=0, columnspan=2, pady=10)
    entrada = tk.Entry(ventana, show="*")
    entrada.grid(row=1, column=0, columnspan=2)

    tk.Button(ventana, text="Cambiar",
              command=lambda: cambiar_contraseña(entrada.get())
    ).grid(row=2, column=0, columnspan=2, pady=10)

def cambiar_contraseña(nueva_pw):
    if nueva_pw.strip() == "":
        mostrar_mensaje("La contraseña no puede estar vacía")
        ventana.after(1500, pedir_nueva_contraseña)
        return

    hashed = bcrypt.hashpw(nueva_pw.encode(), bcrypt.gensalt()).decode()
    guardar_password(hashed)

    mostrar_mensaje("Contraseña cambiada")
    ventana.after(1500, menu_cambio)

def verificar_contraseña(pw_introducida):
    guardada = cargar_datos()

    if guardada == "unknown":
        # Primera contraseña
        hashed = bcrypt.hashpw(pw_introducida.encode(), bcrypt.gensalt()).decode()
        guardar_password(hashed)
        mostrar_mensaje("Contraseña creada")
        ventana.after(1500, menu_cambio)
        return

    # Verificar bcrypt
    if bcrypt.checkpw(pw_introducida.encode(), guardada.encode()):
        mostrar_mensaje("Acceso permitido")
        ventana.after(1500, menu_cambio)
    else:
        mostrar_mensaje("Acceso denegado")
        ventana.after(1500, pedir_contraseña)

# --------- INICIO ---------

pedir_contraseña()
ventana.mainloop()
