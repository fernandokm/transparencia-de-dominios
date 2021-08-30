# Consultas Disponíveis

Todas as consultas listadas aqui devem ser realizadas como requisições HTTP GET
para o servidor de DT.

## Obter a última cabeça de mapa assinada (SMH)

- Consulta: `/dt/v1/get-smh`
- Entradas: nenhuma
- Saídas:
  - `timestamp` (número): o instante em que a cabeça foi gerada
  - `map_size` (número): o tamanho do mapa
  - `map_root_hash` (base64): a raiz do mapa
  - `source_tree_root_hash` (base64): a raiz da árvore fonte
  - `source_log_revisions`(lista):
    um objeto por log fonte, com as seguintes chaves:
    - `tree_size` (número): o tamanho do respectivo log fonte
    - `root_hash` (base64): a raiz do respectivo log fonte
  - `map_head_signature` (base64): a assinatura da cabeça de mapa

## Obter a última raiz de árvore de domínio

- Consulta: `/dt/v1/get-domain-root-and-proof`
- Entradas:
  - `domain_name` (string): o nome do domínio
  - `domain_map_size` (número): o tamanho do mapa de domínios, que deve se referir uma cabeça válida
- Saídas:
  - `domain_tree_size` (número): o número de folhas na árvore de domínio
  - `domain_tree_root_hash` (base64): a raiz da árvore de domínio
  - `normalized_domain_name` (string): o nome de domínio normalizado referente à árvore de domínio
  - `audit_path` (lista de base64): uma prova de auditoria dessa árvore de domínio

## Verificar que duas revisões de uma árvore de domínio são consistentes

- Consulta: `/dt/v1/get-consistency-proof`
- Entradas:
  - `domain_name` (string): o nome do domínio
  - `first` (número): o tamanho da primeira revisão da árvore de domínio
  - `second` (número): o tamanho da segunda revisão da árvore de domínio
- Saída:
  - `proof` (lista de base64): uma prova de consistência entre as duas revisões especificadas da árvore de domínio

## Obter um intervalo de entradas de uma árvore de domínio

- Consulta: `/dt/v1/get-entries`
- Entradas:
  - `domain_name` (string): o nome do domínio
  - `start` (número): o índice do primeiro certificado
  - `end` (número): o índice do último certificado
- Saída:
  - `entries` (lista de [número, número]): uma lista de pares `(i,j)`,
    onde cada par se refere ao certificado no índice `j` do `i`-ésimo log fonte

## Verificar que um certificado está presente em uma árvore de domínio

- Consulta: `/dt/v1/get-entry-and-proof`
- Entradas:
  - `domain_name` (string): o nome do domínio
  - `index` (número): o índice do certificado
  - `domain_tree_size` (número): o número de folhas na árvore de domínio
- Saída:
  - `entry` ([número, número]): um par `(i,j)`, referenciando o certificado
    no índice `j` do `i`-ésimo log fonte
  - `audit_path` (lista de base64): uma prova de auditoria desse certificado

## Converter um índice de log fonte para índice de uma árvore de domínio

- Consulta: `/dt/v1/get-domain-tree-index`
- Entradas:
  - `domain_name` (string): o nome do domínio
  - `log_index` (número): o índice de um log fonte
  - `certificate_index` (número): o índice de um certificado no log fonte especificado
- Saída:
  - `domain_tree_index` (número): o índice do certificado na árvore de domínio especificada

## Obter um intervalo de entradas da árvore fonte

- Consulta: `/dt/v1/get-source-logs`
- Entradas:
  - `start` (número): o índice do primeiro log
  - `end` (número): o índice do último log
- Saída:
  - `log_ids` (lista de base64): uma lista de IDs dos logs fonte pedidos

## Verificar que um log fonte está presente na árvore fonte

- Consulta: `/dt/v1/get-source-log-and-proof`
- Entradas:
  - `index` (número): o índice do log fonte
  - `source_tree_size` (número): o número de folhas na árvore fonte
- Saída:
  - `log_id` (lista de base64): o ID do log fonte pedido
  - `audit_path` (lista de base64): uma prova de auditoria do log fonte

## Verificar que duas revisões da árvore fonte

- Consulta: `/dt/v1/get-source-consistency-proof`
- Entradas:
  - `first` (número): o tamanho da primeira revisão da árvore fonte
  - `second` (número): o tamanho da segunda revisão da árvore fonte
- Saída:
  - `proof` (lista de base64): uma prova de consistência entre as duas revisões especificadas da árvore fonte
