# Transparência de Domínios

Este é o repositório de Transparência de Domínios. Transparência de Domínios é
um protocolo proposto com o objetivo de facilitar a identificação confiável
de certificados TLS fraudulentos.

## Obtenção e Configuração da Ferramenta

A ferramenta de Transparencia de Domínios utiliza a linguagem go.
Para compilá-la, utilize os seguintes comandos:

```bash
go build github.com/fernandokm/transparencia-de-dominios/cmd/run-server
go build github.com/fernandokm/transparencia-de-dominios/cmd/track-domain
```

Esses comandos gerarão dois binários (`run-server` e `track-domain`)
no diretório atual.

Para executar a ferramenta, também é necessário criar uma pasta "config"
no diretório atual:

```bash
mkdir config
```

## Execução da Ferramenta

Para executar a ferramenta com logs de CT reais, escolha um ou mais logs
(e.g. [nessa lista](https://ct.cloudflare.com/logs) ou
[nessa lista](https://www.gstatic.com/ct/log_list/v2/log_list.json))
copie as suas URLs e inicie o servidor com o seguinte comando:

```bash
./run-server --log https://link-do-log-1 --log https://link-do-log-2 ...
```

O servidor pode demorar um pouco para começar a funcionar, pois o mapa
só pode começar a operar quando todos os certificados dos logs forem
recuperados.

A API é disponibilizada em `127.0.0.1:8021`. Para verificar que ela está
funcionando, tente carregar a url `http://127.0.0.1:8021/dt/v1/get-smh`.
Uma lista completa de todas as consultas possíveis pode ser vista
[aqui](API.md).

O programa `track-domain` simplifica o processo de verificação
dos certificados de um domínio. Ele rastreia um mapa de domínios
e notifica o usuário de quaisquer novos certificados em um dado domínio:

```bash
./track-domain --domain DOMINIO-DE-INTERESSE
```
