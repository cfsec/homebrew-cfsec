class Cfsec < Formula
  desc "Static analysis security scanner for your CloudFormation code"
  homepage "https://cfsec.dev/"
  url "https://github.com/aquasecurity/cfsec/archive/v0.0.6.tar.gz"
  sha256 "791b9690a4726b6c9361fe277805136281b3b892021f4461be208fc2d92d3d95"
  license "MIT"
  head "https://github.com/aquasecurity/cfsec.git", branch: "master"

  livecheck do
    url :stable
    strategy :github_latest
  end

  depends_on "go" => :build

  def install
    system "scripts/install.sh", "v#{version}"
    bin.install "cfsec"
  end

  test do
    (testpath/"good/brew-validate.yaml").write <<~EOS
      Parameters:
        BucketName:
          Type: String
          Default: naughty
        EncryptBucket:
          Type: Boolean
          Default: true
      Resources:
        S3Bucket:
          Type: 'AWS::S3::Bucket'
          Properties:
            BucketName:
              Ref: BucketName
            PublicAccessBlockConfiguration:
              BlockPublicAcls: true
              BlockPublicPolicy: true
              IgnorePublicAcls: true
              RestrictPublicBuckets: true
            BucketEncryption:
              ServerSideEncryptionConfiguration:
              - BucketKeyEnabled: !Ref EncryptBucket
            VersioningConfiguration:
              Status: Enabled
            LoggingConfiguration:
              DestinationBucketName: logging-bucket
              LogFilePrefix: accesslogs/

    EOS
    (testpath/"bad/brew-validate.yaml").write <<~EOS
      Parameters:
      BucketName:
        Type: String
        Default: naughty
      EncryptBucket:
        Type: Boolean
        Default: false
      Resources:
        S3Bucket:
          Type: 'AWS::S3::Bucket'
          Properties:
            BucketName:
              Ref: BucketName
            PublicAccessBlockConfiguration:
              BlockPublicAcls: true
              BlockPublicPolicy: true
              IgnorePublicAcls: true
              RestrictPublicBuckets: true
            BucketEncryption:
              ServerSideEncryptionConfiguration:
              - BucketKeyEnabled: !Ref EncryptBucket
            VersioningConfiguration:
              Status: Enabled
            LoggingConfiguration:
              DestinationBucketName: logging-bucket
              LogFilePrefix: accesslogs/
    EOS

    good_output = shell_output("#{bin}/cfsec --no-color #{testpath}/good/brew-validate.yaml")
    assert_match "0 potential problems detected.", good_output
    bad_output = shell_output("#{bin}/cfsec --no-color #{testpath}/bad/brew-validate.yaml")
    assert_match "1 potential problems detected.", bad_output
  end
end
