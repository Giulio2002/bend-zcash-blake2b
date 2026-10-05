import Base
import ../bend-collections/src/crypto/blake/blake2b/params.bend as P
import ../bend-collections/src/crypto/blake/blake2b/types.bend as T

# The request loop behind libbendblake2b (bend_blake2b.h). Every hash goes
# through the proved code of src/crypto/blake/blake2b/params.bend; the C side
# (blake2b_ffi.c) only moves words in and out.
#
# A request is (op, (ll, (hdr, (key, msg)))): hdr is 32 words
#   0 nn, 1 kk, 2..5 salt, 6..9 personalization, 10..25 h, 26..29 t, 30 n
# (h and t as low/high U32 halves, little-endian), key and msg are packed
# little-endian byte arrays. The answer is a list of words:
#   op 0  P.blake2b_params(nn, key, kk, salt, personal, msg, ll): [1, the nn
#         digest bytes] or [0] for invalid parameters
#   op 1  P.init(nn, kk, salt, personal): h as 16 words
#   op 2  P.update(n, 0, t, (msg, h)): the n blocks of msg absorbed, h as 16 words
#   op 3  P.finish(msg, ll, t, h, nn): the last block (ll bytes), the nn digest bytes

def Blake.exchange(+xs: +List<U32>) -> IO(U32 & (U32 & (Array<U32> & (Array<U32> & Array<U32>)))):
  import "./blake2b_ffi.c"

# Words 0..n of the array, as a list.
def words(n: Nat, +next: U32, acc: +List<U32>, pair: Array<U32> & U32) -> +List<U32>:
  match n pair:
    case 0n Tuple{a,w}: List.reverse(&2,U32,w <> acc)
    case 1n+p Tuple{a,w}: words(p,U32.inc(next),w <> acc,Array.get(U32,a,next))

def flat(h: T.Chain) -> +List<U32>:
  match h:
    case T.H{T.W{l0,u0},T.W{l1,u1},T.W{l2,u2},T.W{l3,u3},T.W{l4,u4},T.W{l5,u5},T.W{l6,u6},T.W{l7,u7}}:
      [l0,u0,l1,u1,l2,u2,l3,u3,l4,u4,l5,u5,l6,u6,l7,u7]

def answer(r: Maybe<&1,+List<U32>>) -> +List<U32>:
  match r:
    case None{}: [0]
    case Some{bs}: 1 <> bs

def dispatch(+op: U32, +ll: U32, +nn: U32, +kk: U32, salt: T.Words4, personal: T.Words4, h: T.Chain, t: T.Counter, +n: U32, key: Array<U32>, msg: Array<U32>) -> +List<U32>:
  match op:
    case 0: answer(P.blake2b_params(U32.to_nat(nn),key,U32.to_nat(kk),salt,personal,msg,U32.to_nat(ll)))
    case 1: flat(P.init(nn,kk,salt,personal))
    case 2: flat(P.update(U32.to_nat(n),0,t,(msg,h)))
    case _: P.finish(msg,U32.to_nat(ll),t,h,U32.to_nat(nn))

# The header is decoded once: every field is used where it lands.
def run(+op: U32, +ll: U32, hs: +List<U32>, key: Array<U32>, msg: Array<U32>) -> +List<U32>:
  match hs:
    case nn <> kk <> s0 <> s1 <> s2 <> s3 <> p0 <> p1 <> p2 <> p3 <> h0 <> h1 <> h2 <> h3 <> h4 <> h5 <> h6 <> h7 <> h8 <> h9 <> h10 <> h11 <> h12 <> h13 <> h14 <> h15 <> t0 <> t1 <> t2 <> t3 <> n <> rest:
      dispatch(op,ll,nn,kk,T.X4{s0,s1,s2,s3},T.X4{p0,p1,p2,p3},T.H{T.W{h0,h1},T.W{h2,h3},T.W{h4,h5},T.W{h6,h7},T.W{h8,h9},T.W{h10,h11},T.W{h12,h13},T.W{h14,h15}},T.C{t0,t1,t2,t3},n,key,msg)
    case _: [0]

def handle(req: U32 & (U32 & (Array<U32> & (Array<U32> & Array<U32>)))) -> +List<U32>:
  (+op, r1) = req
  (+ll, r2) = r1
  (hdr, r3) = r2
  (key, msg) = r3
  run(op,ll,words(31n,1,[],Array.get(U32,hdr,0)),key,msg)

@unsafe
def serve(+xs: +List<U32>) -> IO(Unit):
  do IO<Unit>:
    req : U32 & (U32 & (Array<U32> & (Array<U32> & Array<U32>))) <- Blake.exchange(xs)
    serve(handle(req))

def main() -> IO(Unit): serve([])
