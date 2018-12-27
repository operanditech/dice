#include <eosiolib/eosio.hpp>
#include <eosiolib/asset.hpp>
#include <eosiolib/crypto.hpp>
#include <string>

using eosio::assert_sha256;
using eosio::checksum256;
using eosio::extended_asset;
using eosio::extended_symbol;
using eosio::name;
using eosio::permission_level;
using eosio::sha256;
using std::string;

CONTRACT dice : public eosio::contract
{
public:
  enum state
  {
    CLOSEABLE,
    COMMITTED,
    RANDOMIZED
  };

  TABLE session_type
  {
    name account;
    extended_asset balance;
    extended_asset house_balance;
    // TODO Add public key fields for the player and the house
    uint32_t nonce = 0;
    state state = CLOSEABLE;
    bool closed = false;

    extended_asset bet;
    uint8_t roll_under;
    checksum256 seed_hash;
    uint64_t random;
    uint64_t reveal_timeout;

    bool validate_signatures(checksum256 signature, checksum256 house_signature)
    {
      // TODO Implement this
      return true;
    }

    static uint64_t compute_primary_key(extended_symbol symbol)
    {
      uint64_t data[2] = {symbol.get_contract().value, symbol.get_symbol().raw()};
      checksum256 hash = sha256((char *)&data, sizeof(data));
      uint64_t result;
      memcpy(&result, &hash, 8);
      return result;
    }
    static uint64_t compute_primary_key(extended_asset balance)
    {
      return compute_primary_key(balance.get_extended_symbol());
    }
    uint64_t primary_key() const { return compute_primary_key(balance); }
  };
  typedef eosio::multi_index<name("sessions"), session_type> sessions_table;

  using contract::contract;

  ACTION opensession(name account, extended_asset deposit)
  {
    eosio_assert(deposit.quantity.amount > 0, "Must deposit a positive amount");
    require_auth(account);

    sessions_table sessions(_self, account.value);
    auto primary_key = session_type::compute_primary_key(deposit);
    auto session = sessions.find(primary_key);
    eosio_assert(session == sessions.end(), "User already has a session open for this token");
    sessions.emplace(account, [&](session_type &session) {
      session.account = account;
      session.balance = deposit;
      session.house_balance = deposit;
      session.nonce = 0;
    });
    eosio::action(permission_level(account, name("active")),
                  deposit.contract, name("transfer"),
                  std::make_tuple(account, _self, deposit.quantity, "Open dice session"))
        .send();
  };

  ACTION closesession(session_type session, checksum256 signature, checksum256 house_signature)
  {
    eosio_assert(session.state == CLOSEABLE, "Provided session is not closeable");
    if (session.closed)
    {
      sessions_table sessions(_self, session.account.value);
      auto primary_key = session_type::compute_primary_key(session.balance);
      const session_type &db_session = sessions.get(primary_key, "Session not found");

      // TODO First make sure the provided session matches the on-chain one in the relevant points
      // such as token contract and symbol, public keys, nonce >= the on-chain one, etc

      eosio_assert(session.validate_signatures(signature, house_signature), "Invalid signatures");
      sessions.erase(db_session);
      eosio::action(permission_level(_self, name("transfer")),
                    session.balance.contract, name("transfer"),
                    std::make_tuple(_self, session.account, session.balance.quantity, "Close dice session"))
          .send();
    }
    else
    {
      // TODO Initiate challenge period
    }
  };

  ACTION commit(name account, extended_asset bet, uint8_t roll_under, checksum256 seed_hash)
  {
    eosio_assert(bet.quantity.amount > 0, "Bet must be a positive amount");
    eosio_assert(roll_under > 1 && roll_under < 100, "Invalid roll under parameter");
    eosio_assert(account != _self, "House can't place a bet against itself");
    require_auth(account);

    sessions_table sessions(_self, account.value);
    auto primary_key = session_type::compute_primary_key(bet);
    const session_type &session = sessions.get(primary_key, "Session not found");
    eosio_assert(!session.closed, "Session already closed");

    sessions.modify(session, eosio::same_payer, [&](session_type &session) {
      session.bet = bet;
      session.roll_under = roll_under;
      session.seed_hash = seed_hash;
      session.nonce++;
      session.state = COMMITTED;
    });
  };

  ACTION randomize(name account, extended_symbol symbol, uint64_t random)
  {
    eosio_assert(account != _self, "House can't be betting against itself");
    require_auth(_self);

    sessions_table sessions(_self, account.value);
    auto primary_key = session_type::compute_primary_key(symbol);
    const session_type &session = sessions.get(primary_key, "Session not found");
    eosio_assert(!session.closed, "Session already closed");

    sessions.modify(session, eosio::same_payer, [&](session_type &session) {
      session.random = random;
      session.reveal_timeout = now() + 5 * 60;
      session.nonce++;
      session.state = RANDOMIZED;
    });
  };

  ACTION reveal(name account, extended_symbol symbol, uint64_t seed)
  {
    eosio_assert(account != _self, "House can't be betting againt itself");

    sessions_table sessions(_self, account.value);
    auto primary_key = session_type::compute_primary_key(symbol);
    const session_type &session = sessions.get(primary_key, "Session not found");
    eosio_assert(!session.closed, "Session already closed");

    if (now() > session.reveal_timeout)
    {
      this->payout(session, false);
    }
    else
    {
      require_auth(account);
      // TODO Calculate who won and execute payout
    }
  };

private:
  void payout(session_type session, bool player_won)
  {
    sessions_table sessions(_self, session.account.value);
    sessions.modify(session, eosio::same_payer, [&](session_type &session) {
      if (player_won)
      {
        session.balance += session.bet;
        session.house_balance -= session.bet;
      }
      else
      {
        session.balance -= session.bet;
        session.house_balance += session.bet;
      }
      session.bet = extended_asset();
      session.roll_under = 0;
      session.seed_hash = checksum256();
      session.random = 0;
      session.reveal_timeout = 0;
      session.nonce++;
      session.state = CLOSEABLE;
    });
  }
};
EOSIO_DISPATCH(dice, (opensession)(closesession)(commit)(randomize)(reveal))
