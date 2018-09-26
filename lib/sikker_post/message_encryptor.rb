require 'openssl'
# https://gist.github.com/VimleshS/168d149eed3681f5bde243a0b59c530e
class MessageEncryptor
  class << self
    include OpenSSL

    def delivering_email(message)
      return unless message.header[:send_as_secure_mail]&.value == 'true'
      encrypted_message = sign_and_encrypt(message.encoded, message.to)
      overwrite_body(message, encrypted_message)
      overwrite_headers(message, encrypted_message)
    end

    private

    def sign_and_encrypt(data, recipients)
      encrypt(sign(data), certificates_for(recipients))
    end

    def sign(data)
      PKCS7.write_smime(PKCS7.sign(certificate, private_key, data, [], PKCS7::DETACHED))
    end

    def encrypt(data, certificates)
      Mail.new(PKCS7.write_smime(PKCS7.encrypt(certificates, data, cipher)))
    end

    def cipher
      @cipher ||= Cipher.new('AES-128-CBC')
    end

    def certificate
      @certificate ||= X509::Certificate.new(File.read(certificate_path))
    end

    def certificate_path
      Rails.root.join('config', 'certificates', 'server.pem')
    end

    def private_key
      @private_key ||= PKey::RSA.new(File.read(private_key_path))
    end

    def private_key_path
      Rails.root.join('config', 'certificates', 'nopassserver.key')
    end

    def certificates_for(recipients)
      recipients.map do |recipient|
        X509::Certificate.new(File.read(certificate_path_for(recipient)))
      end
    end

    def certificate_path_for(recipient)
      Rails.root.join('config', 'certificates', "#{recipient}.pem")
    end

    def overwrite_body(message, encrypted_message)
      message.body = nil
      message.body = encrypted_message.body.encoded
    end

    def overwrite_headers(message, encrypted_message)
      message.content_disposition = encrypted_message.content_disposition
      message.content_transfer_encoding = encrypted_message.content_transfer_encoding
      message.content_type = encrypted_message.content_type
    end
  end
end
