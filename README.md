# Transparência de Domínios

Este é o repositório de Transparência de Domínios (_Domain Transparency_ - DT). Transparência de Domínios é
um protocolo proposto com o objetivo de facilitar a identificação confiável
de certificados TLS fraudulentos.

As instruções para a demonstração dessa ferramenta podem ser encontradas [aqui](demo/README.md).

## Instalação da Ferramenta

Para instalar a ferramenta num sistema Linux, siga as instruções abaixo:

1. Instale em seu sistema a linguagem Go, versão 1.16 ou superior, conforme
   as [instruções oficiais de instalação](https://golang.org/doc/install).
   Instale também o programa [git](https://git-scm.com/downloads)
   (necessário para executar o `git clone` no próximo passo).

2. Para compilar a ferramenta, execute os seguintes comandos no terminal:

   ```bash
   git clone https://github.com/fernandokm/transparencia-de-dominios
   cd transparencia-de-dominios
   go build github.com/fernandokm/transparencia-de-dominios/cmd/run-server
   go build github.com/fernandokm/transparencia-de-dominios/cmd/track-domain
   ```

   Esses comandos instalarão todas as bibliotecas de Go necessárias e
   gerarão dois binários (`run-server` e `track-domain`) no diretório atual.

3. Por último, crie uma pasta "config" no diretório atual:

   ```bash
   mkdir config
   ```

   Essa pasta será utilizada para armazenar as chaves pública e privada do servidor.

**Observação:** as instruções dadas acima compilam a ferramenta com suporte
aos [logs públicos de CT](https://www.gstatic.com/ct/log_list/v2/all_logs_list.json)
conhecidos pelo Google. Para utilizar outros logs, é necessário modificar
o arquivo [util/loglist.json](util/loglist.json) e recompilar a ferramenta.

## Execução do Servidor de DT

1. Primeiramente, escolha um ou mais logs que devem ser rastreados,
   e.g. [nessa lista](https://ct.cloudflare.com/logs) ou
   [nessa lista](https://www.gstatic.com/ct/log_list/v2/log_list.json).

2. Copie as URLs dos logs escolhidos e execute o servidor com o seguinte
   comando:

   ```bash
   ./run-server --log https://link-do-log-1 --log https://link-do-log-2 ...
   ```

   Para indicar que um log ainda não está em operação, utilize o prefixo `t:`
   antes da URL, onde `t` é um número, para indicar que o log só entrará em
   operação após `t` segundos e, portanto, que ele só deve ser adicionado
   ao mapa nesse instante:

   ```bash
   ./run-server --log t1:https://link-do-log-1 --log t2:https://link-do-log-2 ...
   ```

   Note que a ordem dos logs no comando é a ordem que aparecerá na árvore fonte.
   Portanto, logs que entrarão em operação por último devem aparecer no final
   do comando.

   Além de `--log`, as seguintes flags podem ser úteis:

   - `--ip IP`: configura o endereço IP do servidor (valor padrão: `127.0.0.1`)
   - `--port`: configura a porta utilizada pelo servidor (valor padrão: `8021`)
   - `--mmd MMD`: configura o atraso máximo de mesclagem (valor padrão: `1m0s`, i.e., 1 minuto)
   - `--public_key ARQUIVO` e `--private_key ARQUIVO`: indicam os arquivos em que as
     chaves pública e privada devem ser salvas (valores padrão: `config/publickey.pem`
     e `config/privatekey.pem`)
   - `--sth_interval INTERVALO`: indica o intervalo de tempo entre duas verificações
     subsequentes de um mesmo log de CT (as verificações são o momento em que o servidor
     verifica se há novos certificados no log) (valor padrão: `5s`, i.e., 5 segundos)

O servidor pode demorar um pouco para começar a funcionar, pois o mapa
só pode começar a operar quando todos os certificados dos logs forem
recuperados.

## Rastreamento de Domínios

O rastreamento de domínios pode ser feito tanto de forma
[manual](#rastreamento-manual), por meio da API disponibilizada, quanto por meio
da ferramenta [`track-domain`](#rastreamento-automático).

### Rastreamento Manual

Uma API é disponibilizada em `127.0.0.1:8021`. Para verificar que ela está
funcionando, tente carregar a url `http://127.0.0.1:8021/dt/v1/get-smh`,
que deve retornar um objeto JSON com a seguinte estrutura, correspondendo
à última cabeça assinada de mapa disponível:

```json
{
  "timestamp": 1111111111,
  "map_size": 111,
  "map_root_hash": "xxx",
  "source_tree_root_hash": "xxx",
  "source_log_revisions": [
    {
      "tree_size": 11,
      "root_hash": "xxx"
    }
  ],
  "map_head_signature": "xxx"
}
```

Uma lista completa de todas as consultas possíveis pode ser vista [aqui](API.md).
Por exemplo, para obter a raiz de uma árvore de domínio, pode-se utilizar a url
`http://127.0.0.1:8021/dt/v1/get-domain-root-and-proof?domain_map_size=TAMANHO_DO_MAPA&domain_name=NOME_DO_DOMINIO`
com valores apropriados para `TAMANHO_DO_MAPA` e `NOME_DO_DOMINIO`.

### Rastreamento Automático

O programa `track-domain` simplifica o processo de verificação
dos certificados de um domínio. Ele rastreia um mapa de domínios
e notifica o usuário de quaisquer novos certificados em um dado domínio.

Para utilizá-lo, basta executar:

```bash
./track-domain --domain DOMINIO-DE-INTERESSE
```

Por exemplo, ao rastrear o domínio `example.com`, uma saída possível é:

```text
2021/07/10 19:07:00 Domain tracker started...
2021/07/10 19:07:14 New SMH: timestamp=1630344141, size=41, rootHash=eedbed0a..., sourceRootHash=02d0d331..., sourceLogCount=1
2021/07/10 19:07:14 New certificate for example.com:
  SHA-256 Fingerprint: 200FCAFA767C8450ECE644879C062A0CDF52240FE05BB7EB284611C3AEF3EC2E
  Leaf Index: 40
```

Essa saída indica que às 19:07:14, foi identificado uma nova cabeça de mapa
e que essa cabeça inclui um novo certificado para o domínio `example.com`.
