# Transparência de Domínios - Demonstração

## Pré-requisitos

Para rodar a demo, além de ter a ferramenta instalada (conforme descrito no
[README](../README.md)), será necessário rodar logs de CT. As instruções para isso
são dadas abaixo:

1. Instale em seu sistema o [docker](https://www.docker.com/get-started) e
   [docker-compose](https://docs.docker.com/compose/install/), conforme as
   suas instruções oficiais de instalação.

2. Abra o terminal na pasta "demo" e execute os seguintes comandos:

   ```bash
   git clone https://github.com/google/trillian
   git clone https://github.com/google/certificate-transparency-go
   sudo docker-compose build
   sudo docker-compose pull
   ```

   Esses comandos criam os containers do docker necessários para
   executar os logs de CT (dependendo da sua instalação do docker,
   o `sudo` pode não ser necessário).

3. Execute:

   ```bash
   sudo docker-compose up --no-start
   sudo docker-compose up db trillian-log-server trillian-log-signer
   ```

   e espere a mensagem `**** Acting as master for all logs ****`.
   Após ver essa mensagem, mantenha o terminal aberto (não pare o container).

4. Em outro terminal (no mesmo diretório), execute:

   ```bash
   cd trillian
   go run ./cmd/createtree --admin_server=127.0.0.1:8090 --tree_type=LOG
   go run ./cmd/createtree --admin_server=127.0.0.1:8090 --tree_type=LOG
   ```

   Cada um dos dois comandos acima deve ter impresso um ID no terminal.
   Coloque esses IDs no arquivo [ct_config/ct_server.cfg](ct_config/ct_server.cfg),
   nos campos `log_id`:

   ```protobuf
   config {
      log_id: <SAÍDA DO PRIMEIRO COMANDO>
      prefix: "demo-log1"
      roots_pem_file: "/ctfe-config/roots.pem"
      private_key: {
         [type.googleapis.com/keyspb.PEMKeyFile] {
            path: "/ctfe-config/ct1_priv.pem"
         }
      }
   }

   config {
      log_id: <SAÍDA DO SEGUNDO COMANDO>
      prefix: "demo-log2"
      roots_pem_file: "/ctfe-config/roots.pem"
      private_key: {
         [type.googleapis.com/keyspb.PEMKeyFile] {
            path: "/ctfe-config/ct2_priv.pem"
         }
      }
   }
   ```

5. Pare o docker-compose (pressione Ctrl+C no terminal que está executando `docker-compose up ...`)

## Parte 1 - Log Único

Para a primeira parte da demonstração, execute:

```bash
cd demo
sudo docker-compose up
```

para iniciar o log de CT.

Em seguida, inicie o servidor de DT utilizando o seguinte comando em outro terminal:

```bash
./run-server --log http://127.0.0.1:6962/demo-log1/
```

e rode o seguinte comando em outro terminal:

```bash
cd demo
go run ./cmd/add-certificates -part1
```

A saída desse último comando deve indicar que estão sendo adicionados certificados
no log de CT para diversos domínios.

Por fim, execute a ferramenta para rastrear o domínio example-1.com:

```bash
./track-domain --domain example-1.com
```

Na saída da ferramenta, as linhas "New SMH:" indicam que o servidor de DT
acabou de ser atualizado (ocorreu uma nova sincronização com os logs)
e as linhas "New certificate for example-1.com" indicam que um novo certificado foi detectado
para o domínio example-1.com. Observa-se que a ferramenta filtra os resultados
e apresenta apenas os certificados relevantes.

## Parte 2 - Vários Logs

A segunda parte da demonstração é parecida com a primeira, mas utiliza dois logs de CT.

Primeiramente, execute:

```bash
cd demo
sudo docker-compose up
```

para iniciar os logs de CT.

Em seguida, inicie o servidor de DT utilizando o seguinte comando em outro terminal:

```bash
./run-server --log http://127.0.0.1:6962/demo-log1/ --log http://127.0.0.1:6962/demo-log2/
```

e rode o seguinte comando em outro terminal:

```bash
cd demo
go run ./cmd/add-certificates -part2
```

Por fim, execute a ferramenta para rastrear o domínio example-1.com:

```bash
./track-domain --domain example-1.com
```

Verifica-se que a ferramenta obtém os certificados de ambos os logs.
