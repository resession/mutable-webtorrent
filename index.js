const WebTorrent = require('webtorrent')
const sodium = require('sodium-universal')
const sha1 = require('simple-sha1')

const BTPK_PREFIX = 'urn:btpk:'
const BITH_PREFIX = 'urn:btih:'

function verify (signature, message, publicKey) {
  return sodium.crypto_sign_verify_detached(signature, message, publicKey)
}

function sign (message, publicKey, secretKey) {
  const signature = Buffer.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, message, secretKey)
  return signature
}

class MutableWebTorrent extends WebTorrent {
  constructor (options) {
    let finalOptions = options || {
      dht: {
        verify
      }
    }

    if (options) {
      if (options.dht) {
        const dht = { verify, ...options.dht }
        finalOptions = { ...options, dht }
      } else {
        finalOptions = {
          ...options,
          dht: {
            verify
          }
        }
      }
    }

    super(finalOptions)
    this.check()
  }

  // UPDATE TORRENTS

  async check(){
    let tempTorrents = super.torrents.map(data => {return data.own ? '' : {publicKey: data.publicKey, infoHash: data.infoHash, sequence: data.sequence}}).filter(Boolean)
    for(let i = 0;i < tempTorrents.length;i++){
      let test = await this.getResolve(tempTorrents[i].publicKey.toString('hex'))
      if(!test){
        super.remove(tempTorrents[i].infoHash, {destroyStore: false})
      } else if(test.infoHash !== tempTorrents[i].infoHash){
        super.remove(tempTorrents[i].infoHash, {destroyStore: false})
        await this.getAdd({publicKey: tempTorrents[i].publicKey, infoHash: test.infoHash, sequence: test.sequence})
      }
    }
    setTimeout(this.check, 7200000)
  }

  getResolve(publicKey){
    return new Promise(resolve => {
      this.resolve(publicKey, (error, data) => {
        if(error){
          resolve(null)
        } else if(data){
          resolve(data)
        }
      })
    })
  }

  getAdd(data){
    return new Promise(resolve => {
      super.add(data.infoHash, {}, torrent => {
        torrent.publicKey = data.publicKey
        torrent.sequence = data.sequence
        resolve(torrent)
      })
    })
  }

  // UPDATE TORRENTS

  add (magnetURI, options, callback) {
    if (!callback) {
      if (typeof options === 'function') {
        callback = options
        options = null
      } else {
        callback = noop
      }
    }

    if (typeof magnetURI !== 'string') {
      return super.add(magnetURI, options, callback)
    }

    const parsed = new URL(magnetURI)

    const xs = parsed.searchParams.get('xs')

    const isMutableLink = xs && xs.startsWith(BTPK_PREFIX)

    if (!isMutableLink) return super.add(magnetURI, options, callback)

    const publicKeyString = xs.slice(BTPK_PREFIX.length)

    this.resolve(publicKeyString, (err, res) => {
      if (err) return this.emit('error', err)
      if (!res) return this.emit('error', new Error('Unable to resolve magnet link'))

      const urn = `${BITH_PREFIX}${res.infoHash.toString('hex')}`

      const finalMangetURI = magnetURI + `&xt=${urn}`

      super.add(finalMangetURI, options, (torrent) => {
        torrent.publicKey = Buffer.from(publicKeyString, 'hex')
        torrent.sequence = res.sequence || 0
        torrent.own = false

        callback(torrent)
      })
    })
  }

  resolve (publicKeyString, callback) {
    const publicKey = Buffer.from(publicKeyString, 'hex')

    sha1(publicKey, (targetID) => {
      this.dht.get(targetID, (err, res) => {
        if (err) return callback(err)

        try {
          const infoHash = res.v.ih
          const sequence = res.seq

          return callback(null, { infoHash, sequence })
        } catch (parseErr) {
          return callback(parseErr)
        }
      })
    })
  }

  publish (publicKeyString, secretKeyString, infoHashString, options, callback) {
    if (!callback) {
      callback = options
      options = { sequence: 1 }
    } else if (!options) {
      options = { sequence: 1 }
    }
    const buffPubKey = Buffer.from(publicKeyString, 'hex')
    const buffSecKey = Buffer.from(secretKeyString, 'hex')

    sha1(buffPubKey, (targetID) => {
      const dht = this.dht

      const opts = {
        k: buffPubKey,
        // seq: 0,
        v: {
          ih: Buffer.from(infoHashString, 'hex')
        },
        sign: (buf) => {
          return sign(buf, buffPubKey, buffSecKey)
        }
      }

      dht.get(targetID, (err, res) => {
        if (err) return callback(err)

        const sequence = (res && res.seq) ? res.seq + 1 : options.sequence
        opts.seq = sequence

        dht.put(opts, (putErr, hash) => {
          if (putErr) return callback(putErr)

          const magnetURI = `magnet:?xs=${BTPK_PREFIX}${publicKeyString}`

          callback(null, {
            magnetURI,
            infohash: infoHashString,
            sequence
          })
        })
      })
    })
  }

  republish (publicKeyString, callback) {
    if (!callback) {
      callback = () => noop
    }

    const buffPubKey = Buffer.from(publicKeyString, 'hex')

    sha1(buffPubKey, (targetID) => {
      const dht = this.dht

      dht.get(targetID, (err, res) => {
        if (err) {
          callback(err)
          callback = noop
          return
        }

        dht.put(res, (err) => {
          callback(err)
        })
      })
    })
  }

  createKeypair (seed) {
    const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
    const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

    if (seed) {
      sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
    } else { sodium.crypto_sign_keypair(publicKey, secretKey) }

    return { publicKey: publicKey.toString('hex'), secretKey: secretKey.toString('hex') }
  }

  pub(folder, options, callback){
    if (!callback) {
      if (typeof options === 'function') {
        callback = options
        options = {}
      } else {
        if(!options){
          options = {}
        }
        callback = noop
      }
    }
    if(options.publicKey && options.privateKey){
      for(let i = 0;i < super.torrents.length;i++){
        if(super.torrents[i].own && super.torrents[i].publicKey.toString('hex') === options.publicKey){
          super.remove(super.torrents[i].infoHash, {destroyStore: false})
          break
        }
      }
    } else {
      let keypair = this.createKeypair(false)
      options.publicKey = keypair.publicKey
      options.privateKey = keypair.secretKey
    }
    // const publicKeyString = Buffer.from(options.publicKey, 'hex')
    // const secretKeyString = Buffer.from(options.secretKey, 'hex')
    super.seed(folder, options, torrent => {
      torrent.own = true
      this.publish(options.publicKey, options.privateKey, torrent.infoHash, {sequence: 0}, (error, data) => {
        if(error){
          this.remove(torrent.infoHash, {destroyStore: false})
          return this.emit('error', error)
        }
        if(!data){
          this.remove(torrent.infoHash, {destroyStore: false})
          return this.emit('error', new Error('do not have key data'))
        }
        torrent.publicKey = Buffer.from(options.publicKey, 'hex')
        torrent.sequence = data.sequence
        torrent.magnetLink = data.magnetURI
        callback(torrent)
      })
    })
  }
}

module.exports = MutableWebTorrent

function noop () {}
