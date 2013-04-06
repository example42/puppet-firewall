require "#{File.join(File.dirname(__FILE__),'..','spec_helper.rb')}"

describe 'firewall' do
  let(:title) { 'firewall1' }
  let(:node) { 'firewall.example42.com' }
  let(:facts) { { :operatingsystem => 'ubuntu', :osver_maj => 12 } }

  describe 'Test firewall with http rule' do
    let(:params) {
      { 'port'       => '80',
        'protocol'   => 'tcp',
        'enable_v6'  => true,
      }
    }
      
    it { should contain_iptables__rule( "firewall1" ).with(
      'port'  => '80',
      'protocol'  => 'tcp',
      'enable_v6' => true,
      'source'    => '',
      'destination' => ''
    ) }
  end
end
