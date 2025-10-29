// --- 1. IMPORTAÇÕES ---
// Framework do servidor
use actix_web::{web, App, HttpServer, Responder, HttpResponse, post};

// Ferramentas do RSA que já conhecemos
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rsa::rand_core::OsRng;
use actix_cors::Cors;

// Ferramenta para criar as chaves APENAS UMA VEZ
#[macro_use]
extern crate lazy_static;

// Ferramentas para "falar" JSON
use serde::{Deserialize, Serialize};

// --- 2. DEFINIÇÃO DAS CHAVES GLOBAIS ---
// Aqui, geramos as chaves UMA VEZ e as guardamos.
// Elas serão as mesmas para todos os "pedidos".
lazy_static! {
    static ref CHAVE_PRIVADA: RsaPrivateKey = RsaPrivateKey::new(&mut OsRng, 2048).expect("Falha ao gerar chave privada");
    static ref CHAVE_PUBLICA: RsaPublicKey = RsaPublicKey::from(&*CHAVE_PRIVADA);
}

// --- 3. DEFINIÇÃO DAS "MENSAGENS" (JSON) ---

// O que esperamos "receber" do JavaScript (o "Pedido")
#[derive(Deserialize)]
struct MensagemRequest {
    texto: String,
}

// O que vamos "enviar" de volta para o JavaScript (a "Resposta")
#[derive(Serialize)]
struct MensagemResponse {
    original: String,
    criptografado_base64: String,
    descriptografado: String,
}

// --- 4. O "MANIPULADOR" DA ROTA (O "Chef de Cozinha") ---

// Esta função será chamada quando o JS pedir para "/criptografar"
// Ela é 'async' porque a web é assíncrona (não trava)
#[post("/criptografar")]
async fn manipular_pedido(req: web::Json<MensagemRequest>) -> impl Responder {
    println!("Recebi um pedido para criptografar: {}", req.texto);

    let mut rng = OsRng;
    let padding = Pkcs1v15Encrypt;

    // 1. Criptografa
    let texto_bytes = req.texto.as_bytes();
    let texto_criptografado = CHAVE_PUBLICA.encrypt(&mut rng, padding, texto_bytes)
        .expect("Falha ao criptografar");

    // 2. Descriptografa (para provar que funciona)
    let texto_descriptografado_bytes = CHAVE_PRIVADA.decrypt(padding, &texto_criptografado)
        .expect("Falha ao descriptografar");

    // 3. Converte para texto legível
    let texto_descriptografado = String::from_utf8(texto_descriptografado_bytes)
        .expect("Falha ao converter bytes para String");

    // O JavaScript não entende bytes crus, então convertemos para Base64
    let texto_criptografado_base64 = base64::encode(&texto_criptografado);

    // 4. Cria a resposta
    let resposta = MensagemResponse {
        original: req.texto.clone(),
        criptografado_base64: texto_criptografado_base64,
        descriptografado: texto_descriptografado,
    };

    // 5. Envia a resposta em formato JSON
    HttpResponse::Ok().json(resposta)
}

// --- 5. O PONTO DE ENTRADA (LIGANDO O "FOGÃO") ---

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🔥 Servidor API de RSA rodando em http://127.0.0.1:8080");

    HttpServer::new(|| {
        // Configuração do CORS: permite "pedidos" de qualquer lugar
        // Para produção, isso seria mais restrito, mas para nós está perfeito.
        let cors = Cors::default()
            .allow_any_origin()    // Permite qualquer "bairro" (file://, http://, etc.)
            .allow_any_method()   // Permite "POST", "GET", etc.
            .allow_any_header();  // Permite cabeçalhos como "Content-Type"

        App::new()
            .wrap(cors) // "Envolve" sua app com as permissões de CORS
            .service(manipular_pedido) // Registra nosso "Chef"
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}