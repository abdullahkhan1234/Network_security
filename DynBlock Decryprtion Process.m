%//Proposed Algorithm for the Main Decryption Function
% Take Ciphertext input from user
cipher = input('Enter ciphertext : ', 's');
% Take secret key input from user
secret_key = input('Enter secret key (64 bits): ', 's');
%covert secret key into binary form exact 64 bits
secret_key_bin = convertToBinary(secret_key);
%Calculation of parameters a,b,c and blocksize
[a,b,c,blocksize] = blocksizecalc(secret_key_bin);
% for calculating shift_value
% Extract the first 8 bits of 'a'
a_extract = a(1:end-8);
% Perform XOR operation
result =dec2bin(bitxor(bin2dec(a_extract), bin2dec(decimalStrRecovered)));
% Convert the recovered decimal string back to a decimal value
shift_value = bin2dec(result);
%Key Expansion stage
secret_key_modified = keyExp(secret_key_bin,blocksize,a,b,c);
%Blocks Division Stage
blocks = dec_blocks(ciphertext,blocksize);
%Key Scheduler
[keys,k0] = key_scheduler(a,b,c,secret_key_modified, blocks);
% XOR operations
[dec_xor]=dec_ciphertext (blocks, keys);
%Toffoli gate implementation
toffoli_blocks=customToffoli2(keys,k0, dec_xor);
% % %XOR with Keys
%  [first_xor]=dec_xor_keys(toffoli_blocks, keys);
% Call dynamic substitution and dynamic permutattion
decsubstituted_blocks=dec_substitution(toffoli_blocks,a,b,c);
%Cyclic Shift of subblocks
[shifted_blocks, shifted_rows]=dec_cyclic(decsubstituted_blocks,shift_value);
% Call dynamic substitution and dynamic permutattion
decsubstituted_blocks2=dec_substitution(shifted_rows,a,b,c);
decpermutated_blocks= dec_perm(secret_key_bin,decsubstituted_blocks2, a, blocksize);
%Plaintext
[concatenate_bits, extract_originalmessagebits, plaintext]=decplain_text(decpermutated_blocks,lengthoriginalmessage);
fprintf('Ciphertext: <strong>%s</strong>\n', plaintext);

%//Convert Secret Key into Binary Form Function
function secret_key_bin = convertToBinary(secret_key)
% Check if secret_key is binary
if all(secret_key == '0' | secret_key == '1')
    secret_key_bin = secret_key;
else
    % Convert each character to its ASCII value and then to binary
    secret_key_bin = reshape(dec2bin(double(secret_key), 8).', 1, []);
end
% Ensure secret_key_bin is exactly 64 bits
len = length(secret_key_bin);
if len > 64
    % If length is greater than 64, extract only first 64 bits
    secret_key_bin = secret_key_bin(1:64);
elseif len < 64
    % If length is less than 64, repeat secret_key_bin until it reaches the length of exact 64 bits
    repeat_factor = ceil(64 / len);
    secret_key_bin = repmat(secret_key_bin, 1, repeat_factor);
    secret_key_bin = secret_key_bin(1:64);
end
end

%//Function to calculate of a,b,c and block size
function [a,b,c,blocksize] = blocksizecalc(secret_key)
% Divide secret key into 4 equal parts; 16 bits each
part1 = secret_key(1:16);
part2 = secret_key(17:32);
part3 = secret_key(33:48);
part4 = secret_key(49:64);
% Perform 2's complement on each divided parts
part1_2s_complement = dec2bin(bitcmp(bin2dec(part1), 'uint16') + 1, 16);
part2_2s_complement = dec2bin(bitcmp(bin2dec(part2), 'uint16') + 1, 16);
part3_2s_complement = dec2bin(bitcmp(bin2dec(part3), 'uint16') + 1, 16);
part4_2s_complement = dec2bin(bitcmp(bin2dec(part4), 'uint16') + 1, 16);
% Swap the parts as described
temp = part1_2s_complement;
part1_2s_complement = part4_2s_complement;
part4_2s_complement = part3_2s_complement;
part3_2s_complement = part2_2s_complement;
part2_2s_complement = temp;
% Perform XOR between first and second part and save the result in "a"
a = dec2bin(bitxor(bin2dec(part1_2s_complement), bin2dec(part2_2s_complement)), 16);
% Perform XOR between third and fourth part and save the result in "b"
b = dec2bin(bitxor(bin2dec(part3_2s_complement), bin2dec(part4_2s_complement)), 16);
% Perform XOR between "a" and "b" and save the result in "c"
c = dec2bin(bitxor(bin2dec(a), bin2dec(b)), 16);
% Calculate the final output using the given formula
% blocksize = 64 + mod(bin2dec(a)+bin2dec(b)+bin2dec(c),9)*8;
blocksize = 64 + mod(bin2dec(a)+bin2dec(b)+bin2dec(c), mod(bin2dec(c),9)+1)*8;
end

%//Key Expansion Function
function secret_key_modified = keyExp(secret_key,blocksize,a,b,c)
% Modify the secret key as per block size
if blocksize == 72
    secret_key_modified = strcat(secret_key, a(1:8));
elseif blocksize == 80
    secret_key_modified = strcat(secret_key, a);
elseif blocksize == 88
    secret_key_modified = strcat(secret_key, a, b(1:8));
elseif blocksize == 96
    secret_key_modified = strcat(secret_key, a, b);
elseif blocksize == 104
    secret_key_modified = strcat(secret_key, a, b, c(1:8));
elseif blocksize == 112
    secret_key_modified = strcat(secret_key, a, b, c);
elseif blocksize == 120
    secret_key_modified = strcat(secret_key, a, b, c, a(1:8));
elseif blocksize == 128
    secret_key_modified = strcat(secret_key, a, b, c, a);
else % If block size is not any of the above values then do nothing with the secret key.
    secret_key_modified = secret_key;
end
end

%//Block Division Function
function blocks = dec_blocks(ciphertext, blocksize)
% Calculate the number of blocks
nblocks = ceil(length(ciphertext) / blocksize);
% Initialize the output cell array
blocks = cell(1, nblocks);
% Loop through the blocks and assign the corresponding segment of ciphertext
for i = 1:nblocks
    % Calculate the start and end indices of the segment
    start = (i - 1) * blocksize + 1;
    stop = min(i * blocksize, length(ciphertext));
    % Assign the segment to the output cell array
    blocks{i} = ciphertext(start:stop);
end
%convert the cell array to char array
blocks = char(blocks);
end

%//Key Scheduler Function
function [keys,k0] = key_scheduler(a, b, c, secret_key_modified, blocks)
% Initialize k1 as secret_key_modified
k1 = secret_key_modified;
% Repeat a,b,c until it matches the length of k1 and name it k0
k0 = [a b c];
while length(k0) < length(k1)
    k0 = [k0 repmat([a b c], 1, ceil((length(k1)-length(k0))/3))];
end
if length(k0) > length(k1)
    k0 = k0(1:length(k1));
end
no_of_blocks = size(blocks,1);
%%
if no_of_blocks == 1
    keys = k1;
else
    % Apply XOR between k1 and k0 to get k2
    k2 = char(xor(logical(k1 - '0'),logical(k0 - '0')) + '0');
    if no_of_blocks == 2
        keys = [k1;k2];
    else
        % keys = zeros(no_of_blocks,size(blocks,2));
        keys(1,:) = k1;
        keys(2,:) = k2;
        for i = 3:no_of_blocks
            keys(i,:) = char(xor(logical(keys(i-1,:) - '0'),logical(keys(i-2,:) - '0')) + '0');
            keys = char(keys);
        end
    end
end
end

%//XOR Operation between each block and respective keys
function [dec_xor]=dec_ciphertext (blocks, keys)
% Apply XOR between blocks and keys respectively
dec_xor = char(xor(logical(blocks- '0'),logical(keys - '0')) + '0');
%  % Apply AND operation between XOR result and keys respectively
% decand_operation = char(bitand(logical(dec_xor - '0'),logical(keys - '0')) + '0');
end

%//Toffoli Gate Function
function toffoli_blocks = customToffoli2(k,k0,b)
toffoli_blocks = char(xor(and(logical(k - '0'),logical(k0 - '0')),logical(b - '0')) + '0');
end

%//Dynamic Substitution of first round
function decsubstituted_blocks=dec_substitution(dec_xor,a,b,c)
% Concatenate a, b , c and a all 16 bits which is 64 bits
concatenate_abca = [a,b,c,a];
% Extract first 64 bits from and operation result blocks
first_64_bits = dec_xor(1:size(dec_xor,1),1:64);
% Performa XOR between first 64 bits of and operation blocks and
% concatenation of abca
xor_64_bits = char(xor(logical(first_64_bits - '0'),logical(concatenate_abca - '0')) + '0');
% Substitute the XOR result at the first 64 bit position of and
% operation blocks
decsubstituted_blocks = [xor_64_bits, dec_xor(:,65:end)];
end

%//Dynamic Permutation of first round
function [shifted_blocks, shifted_rows] = dec_cyclic(dec_xor, shift_value)
% % Ensure shift_value is a real finite integer
% shift_value = round(shift_value);
% Shift the blocks to the right by shift_value positions
shifted_blocks = circshift(dec_xor, [0 shift_value]);
% Get the number of rows in the input matrix
num_rows = size(shifted_blocks, 1);
% Shift the rows circularly
shifted_rows = [shifted_blocks(num_rows, :); shifted_blocks(1:num_rows-1, :)];
end

%//Dynamic Substitution of the second round
function decsubstituted_blocks=dec_substitution(dec_xor,a,b,c)
% Concatenate a, b , c and a all 16 bits which is 64 bits
concatenate_abca = [a,b,c,a];
%%
% Extract first 64 bits from and operation result blocks
first_64_bits = dec_xor(1:size(dec_xor,1),1:64);
% Performa XOR between first 64 bits of and operation blocks and
% concatenation of abca
xor_64_bits = char(xor(logical(first_64_bits - '0'),logical(concatenate_abca - '0')) + '0');
% Substitute the XOR result at the first 64 bit position of and
% operation blocks
decsubstituted_blocks = [xor_64_bits, dec_xor(:,65:end)];
end

%//Dynamic Permutation of the second round
function decpermutated_blocks= dec_perm(secret_key,decsubstituted_blocks, a, blocksize)
% Extract the first 8 bits from the secret key
first_8_bits = secret_key(1:8);
% Extract the first 8 bits from the a
first_8_a_bits= a(1:8);
% Concatenate the two 8-bit values into a single 16-bit value
concatenated_value = [first_8_bits, first_8_a_bits];
% Convert the concatenated value to decimal format
decimal_value = bin2dec(concatenated_value);
% Apply the formula X mod size of blocks (64-128 bits) to the result
result = mod(decimal_value, blocksize);
% Perform a left bitwise rotation on the substituted blocks by the resulting value
decpermutated_blocks = decsubstituted_blocks;
for i = 1:result
    decpermutated_blocks = circshift(decpermutated_blocks, [0,  1]);
end
end

%//Plaintext Conversion Function
function [concatenate_bits,extract_originalmessagebits, plaintext]=decplain_text(decpermutated_blocks,lengthoriginalmessage)
% Concatenate Permutated blocks
concatenate_bits = strjoin(cellstr(decpermutated_blocks),'');
% Extract bit from concatenate bits for just original message length
% (bits) for avoiding dynamic padding
extract_originalmessagebits = concatenate_bits(1:size(concatenate_bits,1),1:str2num (lengthoriginalmessage));
% Convert decimal values to characters
plaintext = char(bin2dec(reshape(extract_originalmessagebits,8,[])'))';
end




