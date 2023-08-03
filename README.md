# my-server-file

1 - No terminal, navegue até a pasta do projeto onde está o arquivo `requirements.txt`.

2 - Crie um novo ambiente virtual (substitua `myenv` pelo nome que desejar para o ambiente virtual):

```python
python -m venv env
```

3 - Ative o ambiente virtual:

- No Windows:

```python
env\Scripts\activate
```

- No macOS e Linux:

```python
source env/bin/activate
```

4 - Agora que o ambiente virtual está ativado, instale as dependências usando o `pip` com o arquivo `requirements.txt`:

```python
pip install -r requirements.txt
```

5 - Finalmente, execute o script para iniciar o servidor:

```python
python http_server.py
```

