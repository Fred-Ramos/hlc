import RPi.GPIO as GPIO
import time

# Define o número do pino GPIO que você deseja usar
pin_number = 26

# Configuração inicial do GPIO
GPIO.setmode(GPIO.BCM)
GPIO.setup(pin_number, GPIO.OUT)

try:
    # Escreve no pino GPIO (define-o como LOW)
    GPIO.output(pin_number, GPIO.LOW)
    print("GPIO LOW")
    
    # Aguarda 10 segundos
    time.sleep(5)

finally:
    # Limpeza do GPIO ao finalizar
    GPIO.cleanup()
