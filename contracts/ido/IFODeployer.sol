// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import "./IFOInitializable.sol";
import "./IFOInitializableMerkle.sol";

/**
 * @title IFODeployer
 */
contract IFODeployer is Ownable {
    using SafeERC20 for IERC20;

    uint256 public constant MAX_BUFFER_TIMES = 1 weeks; // 1 weeks

    IFOContract[] public IFOContractAddress;

    event AdminTokenRecovery(address indexed tokenRecovered, uint256 amount);
    event NewIFOContract(address indexed publicAddress,address indexed privateAddress);

    /**
     * @notice Constructor
     */
    constructor() {
    }

    struct IFOContract{
        address publicAddress;
        address privateAddress;//Merkle Offering
    }

    /**
     * @notice It creates the IFO contract and initializes the contract.
     * @param _lpToken: the LP token used
     * @param _offeringToken: the token that is offered for the IFO
     * @param _startTime: the start block for the IFO
     * @param _endTime: the end block for the IFO
     * @param _privateStartTime: the start block for the private IFO
     * @param _privateEndTime: the end block for the private IFO
     * @param _adminAddress: the admin address for handling tokens
     */
    function createIFO(
        address _lpToken,
        address _offeringToken,
        uint256 _startTime,
        uint256 _endTime,
        uint256 _privateStartTime,
        uint256 _privateEndTime,
        address _adminAddress,
        bool isPublic,
        bool isPrivate
    ) external onlyOwner {
        require(IERC20(_lpToken).totalSupply() >= 0);
        require(IERC20(_offeringToken).totalSupply() >= 0);
        require(_lpToken != _offeringToken, "Operations: Tokens must be be different");
        require(_endTime < (block.timestamp + MAX_BUFFER_TIMES), "Operations: EndTime too far");
        require(_startTime < _endTime, "Operations: StartTime must be inferior to endTime");
        require(_startTime > block.timestamp, "Operations: StartTime must be greater than current block");
        require(isPublic || isPrivate,"Operations:must Public or Private");

        IFOContract memory ifoContract = IFOContract({publicAddress:address(0),privateAddress:address(0)});
        if(isPublic){
            bytes memory bytecode = type(IFOInitializable).creationCode;
            bytes32 salt = keccak256(abi.encodePacked(_lpToken, _offeringToken, _startTime));
            address ifoAddress;

            assembly {
                ifoAddress := create2(0, add(bytecode, 32), mload(bytecode), salt)
            }

            IFOInitializable(ifoAddress).initialize(
                _lpToken,
                _offeringToken,
                _startTime,
                _endTime,
                MAX_BUFFER_TIMES,
                _adminAddress
            );

            ifoContract.publicAddress = ifoAddress;
        }
        if(isPrivate){
            bytes memory bytecode = type(IFOInitializableMerkle).creationCode;
            bytes32 salt = keccak256(abi.encodePacked(_lpToken, _offeringToken, _startTime));
            address ifoAddress;

            assembly {
                ifoAddress := create2(0, add(bytecode, 32), mload(bytecode), salt)
            }

            IFOInitializableMerkle(ifoAddress).initialize(
                _lpToken,
                _offeringToken,
                _privateStartTime,
                _privateEndTime,
                MAX_BUFFER_TIMES,
                _adminAddress
            );

            ifoContract.privateAddress = ifoAddress;
        }

        IFOContractAddress.push(ifoContract);


        emit NewIFOContract(ifoContract.publicAddress,ifoContract.privateAddress);
    }

    /**
     * @notice It allows the admin to recover wrong tokens sent to the contract
     * @param _tokenAddress: the address of the token to withdraw
     * @dev This function is only callable by admin.
     */
    function recoverWrongTokens(address _tokenAddress) external onlyOwner {
        uint256 balanceToRecover = IERC20(_tokenAddress).balanceOf(address(this));
        require(balanceToRecover > 0, "Operations: Balance must be > 0");
        IERC20(_tokenAddress).safeTransfer(address(msg.sender), balanceToRecover);

        emit AdminTokenRecovery(_tokenAddress, balanceToRecover);
    }



    function getIFOContractAddress(uint256 _amounts, uint256 _offset) external view returns (IFOContract [] memory){
        uint256 i = _offset;
        uint256 ifoAllLen = IFOContractAddress.length;
        if (_amounts > ifoAllLen){
            _amounts = ifoAllLen;
        }
        uint256 _showLength = _offset + _amounts;
        if(_showLength > ifoAllLen){
            _showLength = ifoAllLen;
        }
        IFOContract [] memory ifoConAddr = new IFOContract[](_showLength);
        for(i; i < _showLength; i++){
            if(i == ifoAllLen) {
                break;
            }
            ifoConAddr[i - _offset] = IFOContractAddress[i];
        }
        return ifoConAddr;
    }
}
