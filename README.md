# Body Link Atlas — 公開リポジトリ向け強化ロック版

GitHub Pagesで公開できる、HTML / CSS / JavaScriptのみの静的Webアプリです。

## この版の違い

- `data/keywords.json` と `data/relations.json` は公開フォルダに入れていません。
- 学習データは `data/encrypted-data.json` として暗号化されています。
- 閲覧時に入力したパスワードからブラウザ内で鍵を作り、AES-GCMで復号します。
- パスワード本文やパスワードハッシュはソースコード内に置いていません。

## 重要な注意

これは公開リポジトリ向けの「静的サイトとしてできる範囲の強化」です。サーバー認証ではありません。

- リポジトリ内のファイル自体は公開されます。
- `encrypted-data.json` は暗号文なので、強いパスワードを使うことが前提です。
- 平文の `keywords.json` / `relations.json` / 書き出した `*.private.json` は絶対に公開リポジトリへアップロードしないでください。
- 患者情報、学校名、個人情報、非公開メモは入れない運用を推奨します。

## データを追加・修正する手順

1. サイトにログインします。
2. 「JSON追加テンプレート」画面から、現在の復号済みデータを書き出します。
3. PC内で `keywords.private.json` と `relations.private.json` を編集します。
4. `tools/encrypt.html` をブラウザで開きます。
5. 編集済みJSONを貼り付け、パスワードを入力して `encrypted-data.json` を作成します。
6. 作成した `encrypted-data.json` を `data/encrypted-data.json` と差し替えます。
7. GitHubに commit / push します。

## GitHub Pagesに置くファイル

このフォルダ全体をリポジトリに置けます。ただし、平文JSONは含めないでください。

```text
body-link-atlas-public-secure/
├─ index.html
├─ style.css
├─ app.js
├─ data/
│  └─ encrypted-data.json
├─ tools/
│  └─ encrypt.html
├─ .gitignore
└─ README.md
```

## ローカル確認

`index.html` を直接開くとブラウザ制限で読み込みに失敗することがあります。VS Code の Live Server などで開いてください。
