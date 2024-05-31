import yargs from 'yargs';
import { verify } from '../../src/index';

/**
 * Usage: 
  yarn script etc/script/verifyPowo.ts \
  --proof="eyJleHBpcmVzIjoiMjAyMS0xMS0xN1QxNDoyMDowNi41MDhaIiwidmVyaWZpZXJBZGRyZXNzIjoiaHR0cHM6Ly9wYXNzdjItZGV2LmNpdmljLmNvbSJ9.MHhlMWFjYmQxYmY1MjI4NGNjNDdmZmYzNmFjOWY0NTVlZWY4ZGU2NDg3MGZkMTQ4NmFlNGYyOThmZGNjNzI5Zjc4NWI3MTg0NWEwNTcxNWFiMTE2MmQwZjc3ZjI5ODBmMzQ2ZGUyODc5NjI3NjljODgwYzQyYjc3NWMzNWY1NTVhNjFi" \
  --address='0x155aA83Ab72228d07E8ACd1477653688dA28e507'
 */
(async () => {
  const args = await yargs
    .option('proof', {
      string: true,
    })
    .option('address', {
      string: true,
    })
    .option('message', {
      string: true,
    }).argv;
  console.log(args);

  const { proof, address } = args;
  console.log('Attempting to verify ICP principals', proof);
  const result = await verify(address as string, proof as string, {
    message: 'https://passv2-dev.civic.com',
  });
  console.log(`Verify result: ${result}`);
})();
