import bcrypt

def cargar_datos():
    with open("datos.txt", "r") as archivo:
        lineas = archivo.readlines()

    datos = {}
    for linea in lineas:
        clave, valor = linea.strip().split(":")
        datos[clave] = valor
    return datos

password = input("Dime tu contraseña: ").encode()

# Cargar datos desde el archivo
datos = cargar_datos()

# Si la contraseña guardada es "unknown", significa que no hay contraseña creada
if datos["password"] == "unknown":

    # Crear hash NUEVO y guardarlo
    hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode()

    with open("datos.txt", "w") as archivo:
        archivo.write(f"password:{hashed}\n")

    print("Acceso permitido")

    # Menú para cambiar la contraseña
    while True:
        respuesta = input("Quieres cambiar la contraseña? ")
        if respuesta.lower() == "si":
            password = input("Dime la nueva contraseña: ").encode()
            hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode()

            with open("datos.txt", "w") as archivo:
                archivo.write(f"password:{hashed}\n")

            print("Contraseña cambiada exitosamente")
        else:
            print("Saliendo de la app...")
            break

else:
    # Recuperar el hash guardado en el archivo
    password_guardada = datos["password"].encode()

    # Verificar contraseña ingresada contra hash guardado
    if bcrypt.checkpw(password, password_guardada):
        print("Acceso permitido")
        while True:
            respuesta = input("Quieres cambiar la contraseña? ")
            if respuesta.lower() == "si":
                password = input("Dime la nueva contraseña: ").encode()
                hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode()

                with open("datos.txt", "w") as archivo:
                    archivo.write(f"password:{hashed}\n")

                print("Contraseña cambiada exitosamente")
            else:
                print("Saliendo de la app...")
                break
    else:
        print("Acceso denegado")
        while True:
            respuesta = input("Quieres probar otra vez?")
            if respuesta.lower() == "si":
                password = input("Dime tu contraseña: ").encode()
                password_guardada = datos["password"].encode()
                if bcrypt.checkpw(password, password_guardada):
                    print("Acceso permitido")
                    while True:
                        respuesta = input("Quieres cambiar la contraseña? ")
                        if respuesta.lower() == "si":
                            password = input("Dime la nueva contraseña: ").encode()
                            hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode()

                            with open("datos.txt", "w") as archivo:
                                archivo.write(f"password:{hashed}\n")

                            print("Contraseña cambiada exitosamente")
                        else:
                            print("Saliendo de la app...")
                            break
                    break

                else:
                    print("contraseña incorrecta")
            else:
                print("Saliendo de la app...")
                break
