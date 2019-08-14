# BastionServer
通信監視用踏み台サーバー

## Usage
`usage: bastion [-http port] [-proxy url]`

## proxyについて
### プション指定有り  
オプションに指定されたプロキシを使用

#### オプション指定無し  
環境変数`https_proxy`,`http_proxy`に設定されている値を使用  
無い場合はそのままリクエスト先に接続する

bastionserverを環境変数に登録する場合はオプションでプロキシ指定を行わないとエラーになる  
環境変数に登録かつbastionからの接続にプロキシを使用しない場合は`-proxy=`でプロキシ無しを指定する
